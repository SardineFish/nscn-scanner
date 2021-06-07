import { Collapse, Descriptions, Divider, List } from "antd";
import Paragraph from "antd/lib/typography/Paragraph";
import React from "react";
import { NetScanResult, ScanResult, SSHScanResult } from "../api/api";
import { ArrayElement } from "../utils/utils";
import { GenericScanResult } from "./generic-scan-result";

export function SSHResultPanel(props: {result: NetScanResult<"ssh", SSHScanResult>})
{
    const data = props.result;
    return (<>
        <GenericScanResult result={data} scanner="TCPScanner::SSH" />
        {
            data.result === "Ok"
                ? <>
                    <Divider orientation="left">SSH Server</Divider>
                    <Descriptions>
                        <Descriptions.Item label="SSH Version">{`${data.data.protocol.version}`}</Descriptions.Item>
                        <Descriptions.Item label="Software">{data.data.protocol.software}</Descriptions.Item>
                        <Descriptions.Item label="Comments">{data.data.protocol.comments}</Descriptions.Item>
                    </Descriptions>
                    <Divider orientation="left">Server Key Exchange Algorithm</Divider>
                    <Collapse>
                        {Object.keys(data.data.algorithm).map((key, idx) => (
                            <Collapse.Panel header={key} key={idx}>
                                <List size="small">
                                    {(data.data.algorithm as Record<string, string[]>)[key].map((algo, idx) => (
                                        <List.Item key={idx}>{algo}</List.Item>
                                    ))}
                                </List>
                            </Collapse.Panel>
                        ))}
                    </Collapse>
                </>
                :null
        }
    </>)
}