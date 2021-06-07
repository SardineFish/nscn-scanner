import { Descriptions, Badge, Divider } from "antd";
import Paragraph from "antd/lib/typography/Paragraph";
import React from "react";
import { NetScanResult } from "../api/api";

export function GenericScanResult(props: {result: NetScanResult<string, any>, scanner: string})
{
    const data = props.result;
    return (<>
        <Descriptions>
            <Descriptions.Item label="Scan Port">80</Descriptions.Item>
            <Descriptions.Item label="Result">
                <Badge status={data.result === "Ok" ? "success" : "error"} />
                {data.result === "Ok" ? "success" : "failed"}
            </Descriptions.Item>
            <Descriptions.Item label="Scan Engine">{props.scanner}</Descriptions.Item>
            <Descriptions.Item label="Scan Time">{new Date(data.time.$date).toLocaleString()}</Descriptions.Item>
            <Descriptions.Item label="Used Proxy">{data.proxy}</Descriptions.Item>
        </Descriptions>
        {data.result === "Err"
            ? <>
                <Divider orientation="left">Error Message</Divider>
                <Paragraph>
                    <pre>{data.data}</pre>
                </Paragraph>
            </>
            : null
        }
    </>);
}