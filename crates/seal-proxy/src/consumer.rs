// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::io::Read;

use anyhow::Result;
use axum::{body::Bytes, http::StatusCode};
use bytes::buf::Reader;
use once_cell::sync::Lazy;
use prometheus::{
    opts,
    proto::{LabelPair, MetricFamily},
    Counter, CounterVec, HistogramOpts, HistogramVec, Opts,
};
use prost::Message;
use protobuf::CodedInputStream;

use crate::config::LabelActions;
use crate::{config::LabelModifier, with_label};
use tracing::{debug, error};

use crate::{
    admin::ReqwestClient, middleware::MetricFamilyWithStaticLabels, prom_to_mimir::Mimir,
    register_metric, remote_write::WriteRequest,
};

static CONSUMER_OPS_SUBMITTED: Lazy<Counter> = Lazy::new(|| {
    register_metric!(Counter::with_opts(opts!(
        "consumer_operations_submitted",
        "Operations counter for the number of metric family types we submit, \
excluding histograms, and not the discrete timeseries counts."
    ))
    .unwrap())
});
static CONSUMER_OPS: Lazy<CounterVec> = Lazy::new(|| {
    register_metric!(CounterVec::new(
        Opts::new(
            "consumer_operations",
            "Operations counters and status from operations performed in the consumer."
        ),
        &["operation", "status"]
    )
    .unwrap())
});
static CONSUMER_ENCODE_COMPRESS_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_metric!(HistogramVec::new(
        HistogramOpts::new(
            "protobuf_compression_seconds",
            "The time it takes to compress a remote_write payload in seconds.",
        )
        .buckets(vec![
            1e-08, 2e-08, 4e-08, 8e-08, 1.6e-07, 3.2e-07, 6.4e-07, 1.28e-06, 2.56e-06, 5.12e-06,
            1.024e-05, 2.048e-05, 4.096e-05, 8.192e-05,
        ]),
        &["operation"]
    )
    .unwrap())
});
static CONSUMER_OPERATION_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_metric!(HistogramVec::new(
        HistogramOpts::new(
            "consumer_operations_duration_seconds",
            "The time it takes to perform various consumer operations in seconds.",
        )
        .buckets(vec![
            0.0008, 0.0016, 0.0032, 0.0064, 0.0128, 0.0256, 0.0512, 0.1024, 0.2048, 0.4096, 0.8192,
            1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 2.75, 3.0, 3.25, 3.5, 3.75, 4.0, 4.25, 4.5, 4.75,
            5.0, 5.25, 5.5, 5.75, 6.0, 6.25, 6.5, 6.75, 7.0, 7.25, 7.5, 7.75, 8.0, 8.25, 8.5, 8.75,
            9.0, 9.25, 9.5, 9.75, 10.0, 10.25, 10.5, 10.75, 11.0, 11.25, 11.5, 11.75, 12.0, 12.25,
            12.5, 12.75, 13.0, 13.25, 13.5, 13.75, 14.0, 14.25, 14.5, 14.75, 15.0, 15.25, 15.5,
            15.75, 16.0, 16.25, 16.5, 16.75, 17.0, 17.25, 17.5, 17.75, 18.0, 18.25, 18.5, 18.75,
            19.0, 19.25, 19.5, 19.75, 20.0, 20.25, 20.5, 20.75, 21.0, 21.25, 21.5, 21.75, 22.0,
            22.25, 22.5, 22.75, 23.0, 23.25, 23.5, 23.75, 24.0, 24.25, 24.5, 24.75, 25.0, 26.0,
            27.0, 28.0, 29.0, 30.0,
        ]),
        &["operation"]
    )
    .expect("consumer_operations_duration_seconds"))
});

#[allow(missing_debug_implementations)]
pub struct ProtobufDecoder {
    buf: Reader<Bytes>,
}

impl ProtobufDecoder {
    /// create a new ProtobufDecoder
    pub fn new(buf: Reader<Bytes>) -> Self {
        Self { buf }
    }
    /// parse a delimited buffer of protobufs. this is used to consume data sent
    /// from a sui-node
    pub fn parse<T: protobuf::Message>(&mut self) -> Result<Vec<T>> {
        let timer =
            with_label!(CONSUMER_OPERATION_DURATION, "decode_len_delim_protobuf").start_timer();
        let mut result: Vec<T> = vec![];
        while !self.buf.get_ref().is_empty() {
            let len = {
                let mut is = CodedInputStream::from_buffered_reader(&mut self.buf);
                is.read_raw_varint32()
            }?;
            let mut buf = vec![0; len as usize];
            self.buf.read_exact(&mut buf)?;
            result.push(T::parse_from_bytes(&buf)?);
        }
        timer.observe_duration();
        Ok(result)
    }
}

/// Label allows for static labels to be applied to incoming metrics
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub struct Label {
    /// name of the label
    pub name: String,
    /// value of the label
    pub value: String,
}

/// populate labels in place for our given metric family data
pub fn populate_labels(
    // we will use this for the host field in grafana, this is sourced
    // from the stakingObject data on chain
    node_name: String,
    // labels to apply from local config from walrus-proxy
    label_actions: LabelActions,
    // labels and metric data sent to use from the node
    data: MetricFamilyWithStaticLabels,
    // IP address of the incoming request
    client_ip: String,
) -> Vec<MetricFamily> {
    let timer = with_label!(CONSUMER_OPERATION_DURATION, "populate_labels").start_timer();
    debug!("received metrics from {node_name}");

    let mut to_add_labels = Vec::new();
    let to_remove_labels = label_actions.get(&LabelModifier::Remove);

    if let Some(add_labels) = label_actions.get(&LabelModifier::Add) {
        to_add_labels = add_labels
            .iter()
            .map(|(name, value)| Label {
                name: name.to_owned(),
                value: value.to_owned(),
            })
            .collect();
    }

    let mut node_name_pair = LabelPair::new();
    node_name_pair.set_name("node_name".to_string());
    node_name_pair.set_value(node_name);

    let mut client_ip_pair = LabelPair::new();
    client_ip_pair.set_name("client_ip".to_string());
    client_ip_pair.set_value(client_ip);

    // merge our node provided labels, careful not to overwrite any labels we
    // specified in our config.  our labels take precedence
    let label_pairs: Vec<_> = to_add_labels
        .iter()
        .chain(
            data.labels
                .iter()
                .flatten()
                .filter(|label| !to_add_labels.iter().any(|l| l.name == label.name)),
        )
        .map(|Label { name, value }| {
            let mut label = LabelPair::default();
            label.set_name(name.to_owned());
            label.set_value(value.to_owned());
            label
        })
        // add the node name and client IP labels to the list of labels to identify the source of the metrics
        .chain(vec![node_name_pair, client_ip_pair])
        .collect();

    // apply all of the labels we made here to all of the metrics we received from the node
    let mut metric_families = data.metric_families;
    metric_families
        .iter_mut()
        .flat_map(|mf| mf.mut_metric())
        .for_each(|m| {
            m.mut_label().extend(label_pairs.clone());
            // if the metric has a label that is in the remove_labels list, remove it
            m.mut_label().retain(|label| {
                if let Some(remove_labels) = to_remove_labels {
                    !remove_labels.contains_key(label.get_name())
                } else {
                    true
                }
            });
        });

    timer.observe_duration();
    metric_families
}

// encode and compress our metric data before it gets sent to mimir
fn encode_compress(request: &WriteRequest) -> Result<Vec<u8>, (StatusCode, &'static str)> {
    let observe = || {
        let timer = with_label!(
            CONSUMER_ENCODE_COMPRESS_DURATION,
            "encode_compress"
        )
        .start_timer();
        || {
            timer.observe_duration();
        }
    }();
    let mut buf = Vec::with_capacity(request.encoded_len());
    if request.encode(&mut buf).is_err() {
        observe();
        with_label!(CONSUMER_OPS, "encode_compress", "failed").inc();
        error!("unable to encode prompb to mimirpb");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to encode prompb to remote_write pb",
        ));
    };

    let mut s = snap::raw::Encoder::new();
    let compressed = match s.compress_vec(&buf) {
        Ok(compressed) => compressed,
        Err(error) => {
            observe();
            with_label!(CONSUMER_OPS, "encode_compress", "failed").inc();
            error!("unable to compress to snappy block format; {error}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to compress to snappy block format",
            ));
        }
    };
    observe();
    with_label!(CONSUMER_OPS, "encode_compress", "success").inc();
    Ok(compressed)
}

async fn check_response(
    request: WriteRequest,
    response: reqwest::Response,
) -> Result<(), (StatusCode, &'static str)> {
    match response.status() {
        reqwest::StatusCode::OK => {
            with_label!(CONSUMER_OPS, "check_response", "OK").inc();
            debug!("({}) SUCCESS: {:?}", reqwest::StatusCode::OK, request);
            Ok(())
        }
        reqwest::StatusCode::BAD_REQUEST => {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "response body cannot be decoded".into());

            // see mimir docs on this error condition. it's not actionable from the proxy
            // so we drop it.
            if body.contains("err-mimir-sample-out-of-order") {
                with_label!(CONSUMER_OPS, "check_response", "BAD_REQUEST").inc();
                error!("({}) ERROR: {:?}", reqwest::StatusCode::BAD_REQUEST, body);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "IGNORING METRICS due to err-mimir-sample-out-of-order",
                ));
            }
            with_label!(CONSUMER_OPS, "check_response", "INTERNAL_SERVER_ERROR").inc();
            error!("({}) ERROR: {:?}", reqwest::StatusCode::BAD_REQUEST, body);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "unknown bad request error encountered in remote_push",
            ))
        }
        code => {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "response body cannot be decoded".into());
            with_label!(CONSUMER_OPS, "check_response", "INTERNAL_SERVER_ERROR").inc();
            error!("({}) ERROR: {:?}", code, body);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "unknown error encountered in remote_push",
            ))
        }
    }
}

async fn convert(
    mfs: Vec<MetricFamily>,
) -> Result<impl Iterator<Item = WriteRequest>, (StatusCode, &'static str)> {
    let result = tokio::task::spawn_blocking(|| {
        let timer =
            with_label!(CONSUMER_OPERATION_DURATION, "convert_to_remote_write_task").start_timer();
        let result = Mimir::from(mfs);
        timer.observe_duration();
        result.into_iter()
    })
    .await;

    let result = match result {
        Ok(v) => v,
        Err(err) => {
            error!("unable to convert to remote_write; {err}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "DROPPING METRICS; unable to convert to remote_write",
            ));
        }
    };
    Ok(result)
}

/// convert_to_remote_write is an expensive method due to the time it takes to
/// submit to mimir. other operations here are optimized for async, within
/// reason.  The post process uses a single connection to mimir and thus incurs
/// the seriliaztion delay for each metric family sent.
pub async fn convert_to_remote_write(
    rc: ReqwestClient,
    node_metric: Vec<MetricFamily>,
) -> (StatusCode, &'static str) {
    let timer = with_label!(CONSUMER_OPERATION_DURATION, "convert_to_remote_write").start_timer();

    let remote_write_protos = match convert(node_metric).await {
        Ok(v) => v,
        Err(err) => {
            timer.stop_and_discard();
            return err;
        }
    };

    // a counter so we don't iterate the node data 2x
    let mut mf_cnt = 0;
    for request in remote_write_protos {
        mf_cnt += 1;
        let compressed = match encode_compress(&request) {
            Ok(compressed) => compressed,
            Err(error) => return error,
        };

        let response = match rc
            .client
            .post(rc.settings.url.to_owned())
            .header(reqwest::header::CONTENT_ENCODING, "snappy")
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .header("X-Prometheus-Remote-Write-Version", "0.1.0")
            .basic_auth(
                rc.settings.username.to_owned(),
                Some(rc.settings.password.to_owned()),
            )
            .body(compressed)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                with_label!(CONSUMER_OPS, "check_response", "INTERNAL_SERVER_ERROR").inc();
                error!("DROPPING METRICS due to post error: {:#?}", error);
                timer.stop_and_discard();
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DROPPING METRICS due to post error",
                );
            }
        };

        match check_response(request, response).await {
            Ok(_) => (),
            Err(err) => {
                timer.stop_and_discard();
                return err;
            }
        }
    }
    CONSUMER_OPS_SUBMITTED.inc_by(f64::from(mf_cnt));
    timer.observe_duration();
    (StatusCode::CREATED, "created")
}
