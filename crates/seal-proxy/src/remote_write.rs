// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::all)]
#![allow(warnings)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetricMetadata {
    /// Represents the metric type, these match the set from Prometheus.
    /// Refer to model/textparse/interface.go for details.
    #[prost(enumeration = "metric_metadata::MetricType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub metric_family_name: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub help: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub unit: ::prost::alloc::string::String,
}
/// Nested message and enum types in `MetricMetadata`.
pub mod metric_metadata {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum MetricType {
        Unknown = 0,
        Counter = 1,
        Gauge = 2,
        Histogram = 3,
        Gaugehistogram = 4,
        Summary = 5,
        Info = 6,
        Stateset = 7,
    }
    impl MetricType {
        /// String value of the enum field names used in the ProtoBuf
        /// definition.
        ///
        /// The values are not transformed in any way and thus are considered
        /// stable (if the ProtoBuf definition does not change) and safe
        /// for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                MetricType::Unknown => "UNKNOWN",
                MetricType::Counter => "COUNTER",
                MetricType::Gauge => "GAUGE",
                MetricType::Histogram => "HISTOGRAM",
                MetricType::Gaugehistogram => "GAUGEHISTOGRAM",
                MetricType::Summary => "SUMMARY",
                MetricType::Info => "INFO",
                MetricType::Stateset => "STATESET",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "UNKNOWN" => Some(Self::Unknown),
                "COUNTER" => Some(Self::Counter),
                "GAUGE" => Some(Self::Gauge),
                "HISTOGRAM" => Some(Self::Histogram),
                "GAUGEHISTOGRAM" => Some(Self::Gaugehistogram),
                "SUMMARY" => Some(Self::Summary),
                "INFO" => Some(Self::Info),
                "STATESET" => Some(Self::Stateset),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Sample {
    #[prost(double, tag = "1")]
    pub value: f64,
    /// timestamp is in ms format, see model/timestamp/timestamp.go for
    /// conversion from time.Time to Prometheus timestamp.
    #[prost(int64, tag = "2")]
    pub timestamp: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Exemplar {
    /// Optional, can be empty.
    #[prost(message, repeated, tag = "1")]
    pub labels: ::prost::alloc::vec::Vec<Label>,
    #[prost(double, tag = "2")]
    pub value: f64,
    /// timestamp is in ms format, see model/timestamp/timestamp.go for
    /// conversion from time.Time to Prometheus timestamp.
    #[prost(int64, tag = "3")]
    pub timestamp: i64,
}
/// A native histogram, also known as a sparse histogram.
/// Original design doc:
/// <https://docs.google.com/document/d/1cLNv3aufPZb3fNfaJgdaRBZsInZKKIHo9E6HinJVbpM/edit>
/// The appendix of this design doc also explains the concept of float
/// histograms. This Histogram message can represent both, the usual
/// integer histogram as well as a float histogram.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Histogram {
    /// Sum of observations in the histogram.
    #[prost(double, tag = "3")]
    pub sum: f64,
    /// The schema defines the bucket schema. Currently, valid numbers
    /// are -4 <= n <= 8. They are all for base-2 bucket schemas, where 1
    /// is a bucket boundary in each case, and then each power of two is
    /// divided into 2^n logarithmic buckets. Or in other words, each
    /// bucket boundary is the previous boundary times 2^(2^-n). In the
    /// future, more bucket schemas may be added using numbers < -4 or >
    /// 8.
    #[prost(sint32, tag = "4")]
    pub schema: i32,
    /// Breadth of the zero bucket.
    #[prost(double, tag = "5")]
    pub zero_threshold: f64,
    /// Negative Buckets.
    #[prost(message, repeated, tag = "8")]
    pub negative_spans: ::prost::alloc::vec::Vec<BucketSpan>,
    /// Use either "negative_deltas" or "negative_counts", the former for
    /// regular histograms with integer counts, the latter for float
    /// histograms.
    ///
    /// Count delta of each bucket compared to previous one (or to zero for 1st
    /// bucket).
    #[prost(sint64, repeated, tag = "9")]
    pub negative_deltas: ::prost::alloc::vec::Vec<i64>,
    /// Absolute count of each bucket.
    #[prost(double, repeated, tag = "10")]
    pub negative_counts: ::prost::alloc::vec::Vec<f64>,
    /// Positive Buckets.
    #[prost(message, repeated, tag = "11")]
    pub positive_spans: ::prost::alloc::vec::Vec<BucketSpan>,
    /// Use either "positive_deltas" or "positive_counts", the former for
    /// regular histograms with integer counts, the latter for float
    /// histograms.
    ///
    /// Count delta of each bucket compared to previous one (or to zero for 1st
    /// bucket).
    #[prost(sint64, repeated, tag = "12")]
    pub positive_deltas: ::prost::alloc::vec::Vec<i64>,
    /// Absolute count of each bucket.
    #[prost(double, repeated, tag = "13")]
    pub positive_counts: ::prost::alloc::vec::Vec<f64>,
    #[prost(enumeration = "histogram::ResetHint", tag = "14")]
    pub reset_hint: i32,
    /// timestamp is in ms format, see model/timestamp/timestamp.go for
    /// conversion from time.Time to Prometheus timestamp.
    #[prost(int64, tag = "15")]
    pub timestamp: i64,
    /// Count of observations in the histogram.
    #[prost(oneof = "histogram::Count", tags = "1, 2")]
    pub count: ::core::option::Option<histogram::Count>,
    /// Count in zero bucket.
    #[prost(oneof = "histogram::ZeroCount", tags = "6, 7")]
    pub zero_count: ::core::option::Option<histogram::ZeroCount>,
}
/// Nested message and enum types in `Histogram`.
pub mod histogram {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ResetHint {
        /// Need to test for a counter reset explicitly.
        Unknown = 0,
        /// This is the 1st histogram after a counter reset.
        Yes = 1,
        /// There was no counter reset between this and the previous Histogram.
        No = 2,
        /// This is a gauge histogram where counter resets don't happen.
        Gauge = 3,
    }
    impl ResetHint {
        /// String value of the enum field names used in the ProtoBuf
        /// definition.
        ///
        /// The values are not transformed in any way and thus are considered
        /// stable (if the ProtoBuf definition does not change) and safe
        /// for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ResetHint::Unknown => "UNKNOWN",
                ResetHint::Yes => "YES",
                ResetHint::No => "NO",
                ResetHint::Gauge => "GAUGE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "UNKNOWN" => Some(Self::Unknown),
                "YES" => Some(Self::Yes),
                "NO" => Some(Self::No),
                "GAUGE" => Some(Self::Gauge),
                _ => None,
            }
        }
    }
    /// Count of observations in the histogram.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Count {
        #[prost(uint64, tag = "1")]
        CountInt(u64),
        #[prost(double, tag = "2")]
        CountFloat(f64),
    }
    /// Count in zero bucket.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ZeroCount {
        #[prost(uint64, tag = "6")]
        ZeroCountInt(u64),
        #[prost(double, tag = "7")]
        ZeroCountFloat(f64),
    }
}
/// A BucketSpan defines a number of consecutive buckets with their
/// offset. Logically, it would be more straightforward to include the
/// bucket counts in the Span. However, the protobuf representation is
/// more compact in the way the data is structured here (with all the
/// buckets in a single array separate from the Spans).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BucketSpan {
    /// Gap to previous span, or starting point for 1st span (which can be
    /// negative).
    #[prost(sint32, tag = "1")]
    pub offset: i32,
    /// Length of consecutive buckets.
    #[prost(uint32, tag = "2")]
    pub length: u32,
}
/// TimeSeries represents samples and labels for a single time series.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimeSeries {
    /// For a timeseries to be valid, and for the samples and exemplars
    /// to be ingested by the remote system properly, the labels field is
    /// required.
    #[prost(message, repeated, tag = "1")]
    pub labels: ::prost::alloc::vec::Vec<Label>,
    #[prost(message, repeated, tag = "2")]
    pub samples: ::prost::alloc::vec::Vec<Sample>,
    #[prost(message, repeated, tag = "3")]
    pub exemplars: ::prost::alloc::vec::Vec<Exemplar>,
    #[prost(message, repeated, tag = "4")]
    pub histograms: ::prost::alloc::vec::Vec<Histogram>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Label {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Labels {
    #[prost(message, repeated, tag = "1")]
    pub labels: ::prost::alloc::vec::Vec<Label>,
}
/// Matcher specifies a rule, which can match or set of labels or not.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LabelMatcher {
    #[prost(enumeration = "label_matcher::Type", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub value: ::prost::alloc::string::String,
}
/// Nested message and enum types in `LabelMatcher`.
pub mod label_matcher {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Eq = 0,
        Neq = 1,
        Re = 2,
        Nre = 3,
    }
    impl Type {
        /// String value of the enum field names used in the ProtoBuf
        /// definition.
        ///
        /// The values are not transformed in any way and thus are considered
        /// stable (if the ProtoBuf definition does not change) and safe
        /// for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Type::Eq => "EQ",
                Type::Neq => "NEQ",
                Type::Re => "RE",
                Type::Nre => "NRE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "EQ" => Some(Self::Eq),
                "NEQ" => Some(Self::Neq),
                "RE" => Some(Self::Re),
                "NRE" => Some(Self::Nre),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadHints {
    /// Query step size in milliseconds.
    #[prost(int64, tag = "1")]
    pub step_ms: i64,
    /// String representation of surrounding function or aggregation.
    #[prost(string, tag = "2")]
    pub func: ::prost::alloc::string::String,
    /// Start time in milliseconds.
    #[prost(int64, tag = "3")]
    pub start_ms: i64,
    /// End time in milliseconds.
    #[prost(int64, tag = "4")]
    pub end_ms: i64,
    /// List of label names used in aggregation.
    #[prost(string, repeated, tag = "5")]
    pub grouping: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Indicate whether it is without or by.
    #[prost(bool, tag = "6")]
    pub by: bool,
    /// Range vector selector range in milliseconds.
    #[prost(int64, tag = "7")]
    pub range_ms: i64,
}
/// Chunk represents a TSDB chunk.
/// Time range [min, max] is inclusive.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Chunk {
    #[prost(int64, tag = "1")]
    pub min_time_ms: i64,
    #[prost(int64, tag = "2")]
    pub max_time_ms: i64,
    #[prost(enumeration = "chunk::Encoding", tag = "3")]
    pub r#type: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// Nested message and enum types in `Chunk`.
pub mod chunk {
    /// We require this to match chunkenc.Encoding.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Encoding {
        Unknown = 0,
        Xor = 1,
        Histogram = 2,
    }
    impl Encoding {
        /// String value of the enum field names used in the ProtoBuf
        /// definition.
        ///
        /// The values are not transformed in any way and thus are considered
        /// stable (if the ProtoBuf definition does not change) and safe
        /// for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Encoding::Unknown => "UNKNOWN",
                Encoding::Xor => "XOR",
                Encoding::Histogram => "HISTOGRAM",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "UNKNOWN" => Some(Self::Unknown),
                "XOR" => Some(Self::Xor),
                "HISTOGRAM" => Some(Self::Histogram),
                _ => None,
            }
        }
    }
}
/// ChunkedSeries represents single, encoded time series.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChunkedSeries {
    /// Labels should be sorted.
    #[prost(message, repeated, tag = "1")]
    pub labels: ::prost::alloc::vec::Vec<Label>,
    /// Chunks will be in start time order and may overlap.
    #[prost(message, repeated, tag = "2")]
    pub chunks: ::prost::alloc::vec::Vec<Chunk>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WriteRequest {
    #[prost(message, repeated, tag = "1")]
    pub timeseries: ::prost::alloc::vec::Vec<TimeSeries>,
    #[prost(message, repeated, tag = "3")]
    pub metadata: ::prost::alloc::vec::Vec<MetricMetadata>,
}
/// ReadRequest represents a remote read request.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadRequest {
    #[prost(message, repeated, tag = "1")]
    pub queries: ::prost::alloc::vec::Vec<Query>,
    /// accepted_response_types allows negotiating the content type of the
    /// response.
    ///
    /// Response types are taken from the list in the FIFO order. If no response
    /// type in `accepted_response_types` is implemented by server, error is
    /// returned. For request that do not contain `accepted_response_types`
    /// field the SAMPLES response type will be used.
    #[prost(enumeration = "read_request::ResponseType", repeated, tag = "2")]
    pub accepted_response_types: ::prost::alloc::vec::Vec<i32>,
}
/// Nested message and enum types in `ReadRequest`.
pub mod read_request {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ResponseType {
        /// Server will return a single ReadResponse message with matched series
        /// that includes list of raw samples. It's recommended to use
        /// streamed response types instead.
        ///
        /// Response headers:
        /// Content-Type: "application/x-protobuf"
        /// Content-Encoding: "snappy"
        Samples = 0,
        /// Server will stream a delimited ChunkedReadResponse message that
        /// contains XOR or HISTOGRAM(!) encoded chunks for a single series.
        /// Each message is following varint size and fixed size bigendian
        /// uint32 for CRC32 Castagnoli checksum.
        ///
        /// Response headers:
        /// Content-Type: "application/x-streamed-protobuf;
        /// proto=prometheus.ChunkedReadResponse" Content-Encoding: ""
        StreamedXorChunks = 1,
    }
    impl ResponseType {
        /// String value of the enum field names used in the ProtoBuf
        /// definition.
        ///
        /// The values are not transformed in any way and thus are considered
        /// stable (if the ProtoBuf definition does not change) and safe
        /// for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ResponseType::Samples => "SAMPLES",
                ResponseType::StreamedXorChunks => "STREAMED_XOR_CHUNKS",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "SAMPLES" => Some(Self::Samples),
                "STREAMED_XOR_CHUNKS" => Some(Self::StreamedXorChunks),
                _ => None,
            }
        }
    }
}
/// ReadResponse is a response when response_type equals SAMPLES.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadResponse {
    /// In same order as the request's queries.
    #[prost(message, repeated, tag = "1")]
    pub results: ::prost::alloc::vec::Vec<QueryResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Query {
    #[prost(int64, tag = "1")]
    pub start_timestamp_ms: i64,
    #[prost(int64, tag = "2")]
    pub end_timestamp_ms: i64,
    #[prost(message, repeated, tag = "3")]
    pub matchers: ::prost::alloc::vec::Vec<LabelMatcher>,
    #[prost(message, optional, tag = "4")]
    pub hints: ::core::option::Option<ReadHints>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryResult {
    /// Samples within a time series must be ordered by time.
    #[prost(message, repeated, tag = "1")]
    pub timeseries: ::prost::alloc::vec::Vec<TimeSeries>,
}
/// ChunkedReadResponse is a response when response_type equals
/// STREAMED_XOR_CHUNKS. We strictly stream full series after series, optionally
/// split by time. This means that a single frame can contain partition of the
/// single series, but once a new series is started to be streamed it means that
/// no more chunks will be sent for previous one. Series are returned sorted in
/// the same way TSDB block are internally.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChunkedReadResponse {
    #[prost(message, repeated, tag = "1")]
    pub chunked_series: ::prost::alloc::vec::Vec<ChunkedSeries>,
    /// query_index represents an index of the query from ReadRequest.queries
    /// these chunks relates to.
    #[prost(int64, tag = "2")]
    pub query_index: i64,
}
