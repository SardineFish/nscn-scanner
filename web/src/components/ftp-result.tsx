import { Descriptions, Divider } from "antd";
import Paragraph from "antd/lib/typography/Paragraph";
import Text from "antd/lib/typography/Text";
import React from "react";
import { FTPScanResult, NetScanResult, ScanResult } from "../api/api";
import { ArrayElement } from "../utils/utils";
import { GenericScanResult } from "./generic-scan-result";

export function FTPScanResult(props: {result: NetScanResult<"ftp", FTPScanResult>})
{
    const data = props.result;
    return (<>
        <GenericScanResult result={data} scanner="TCPScanner::FTP" />
        {
            data.result === "Ok"
                ? <>
                    <Divider orientation="left">FTP Info</Divider>
                    <Descriptions>
                        <Descriptions.Item label="Access">{data.data.access}</Descriptions.Item>
                        <Descriptions.Item label="Reply Code">{data.data.handshake_code}</Descriptions.Item>
                    </Descriptions>
                    <Divider orientation="left">Reply Message</Divider>
                    <Paragraph>
                        <pre>{data.data.handshake_text}</pre>
                    </Paragraph>

                </>
                : null
        }
    </>)
}