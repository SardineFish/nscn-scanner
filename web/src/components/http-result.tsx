import { Badge, Collapse, Descriptions, Divider, Table } from "antd";
import Paragraph from "antd/lib/typography/Paragraph";
import Text from "antd/lib/typography/Text";
import React from "react";
import { ScanResult } from "../api/api";
import { ArrayElement } from "../utils/utils";
import { GenericScanResult } from "./generic-scan-result";

export function HTTPResult(props: { result: ArrayElement<ScanResult["http_results"]>})
{
    const data = props.result;
    if (data.result === "Ok")
    {
        const headers = Object.keys(data.data.headers).map(key => ({
            key: key,
            name: key,
            value: data.data.headers[key].join(", ")
        }));
        const columns = [
            {
                title: "Name",
                dataIndex: "name",
                key: "name"
            },
            {
                title: "Value",
                dataIndex: "value",
                key: "value"
            },
        ]
        return (<>
            <GenericScanResult result={props.result} scanner="HTTPScanner" />
            <Divider orientation="left">HTTP Response</Divider>
            <Descriptions>
                <Descriptions.Item label="Status Code">{data.data.status}</Descriptions.Item>
            </Descriptions>
            <Divider orientation="left">Headers</Divider>
            <Table dataSource={headers} columns={columns} pagination={false} />
            <Divider orientation="left">Body</Divider>
            <Paragraph>
                <pre>{data.data.body}</pre>
            </Paragraph>
        </>)
    }
    else
    {
        return (<>
            <GenericScanResult result={props.result} scanner="HTTPScanner" />
        </>)
    }
}