// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React, { type ReactNode } from "react";
import OriginalCopyButton from "@theme-original/CodeBlock/Buttons/CopyButton";
import type { Props } from "@theme/CodeBlock/Buttons/CopyButton";
import OpenInAgentButton from "../../../../shared/components/OpenInAgentButton";
import OpenInPlayMoveButton from "../../../../shared/components/OpenInPlayMoveButton";

export default function CopyButton(props: Props): ReactNode {
  return (
    <>
      <OriginalCopyButton {...props} />
      <OpenInAgentButton className={props.className} />
      <OpenInPlayMoveButton className={props.className} />
    </>
  );
}
