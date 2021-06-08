import { Badge, Carousel, Collapse, Descriptions, Divider, Drawer, Menu, PageHeader } from "antd";
import { CarouselRef } from "antd/lib/carousel";
import React, { useEffect, useRef, useState } from "react";
import { API, NetScanResult, ScanResult } from "../api/api";
import { HttpsResult } from "./https-result";
import { HTTPResult } from "./http-result";
import { FTPScanResult } from "./ftp-result";
import { SSHResultPanel } from "./ssh-result";
import { VulnsPage } from "./vulns-page";

export function ScanResultDetail(props: { addr: string, visible: boolean, onClose: () => void })
{
    const [page, setPage] = useState(0);
    const [data, setData] = useState<ScanResult | null>(null);
    const [loading, setLoading] = useState(true);
    const ref = useRef<CarouselRef>(null);
    useEffect(() =>
    {
        if (props.visible)
        {

            setPage(0);
            setData(null);
            setLoading(true);
            ref.current?.goTo(0, true);
            (async () =>
            {
                const data = await API.scan.getByIp({ ip: props.addr });
                setData(data[0] || null);
                setLoading(false);
            })();
        }
    }, [props.addr]);
    return (<>
        <Drawer
            className="result-detail"
            visible={props.visible}
            width={800}
            onClose={props.onClose}
            title={(<>
                <PageHeader title={props.addr}></PageHeader>
                <Menu mode="horizontal" selectedKeys={[page.toString()]} onSelect={(props) =>
                {
                    setPage(parseInt(props.key as string));
                    ref.current?.goTo(parseInt(props.key as string));
                }}>
                    <Menu.Item key={0}>Overview</Menu.Item>
                    <Menu.Item key={1}>Vulnerabilities</Menu.Item>
                </Menu>
            </>)}
        >
            {
                data
                    ?
                    <Carousel ref={ref} speed={100}>
                        <Overview data={data} />
                        <VulnsPage result={data} />
                    </Carousel>
                    : null
            }
        </Drawer>
    </>)
}

function Overview(props: { data: ScanResult })
{
    const data = props.data;
    return (<div className="overview">
        <Descriptions title="Scanning">
            <Descriptions.Item label="IP">{data.scan.addr}</Descriptions.Item>
            <Descriptions.Item label="Status">{
                data.scan.online
                    ? <Badge status="success" text="Online"/>
                    : <Badge status="default" text="Offline"/>
            }</Descriptions.Item>
            <Descriptions.Item label="Last Update">{new Date(data.scan.last_update).toLocaleString()}</Descriptions.Item>
            <Descriptions.Item label="Opened Ports">{
                data.scan.results.length > 0
                    ? data.scan.results.map(r=>r.port).join(", ")
                    : "None"
            }</Descriptions.Item>
        </Descriptions>
        <Divider orientation="left">Scanning Results</Divider>
        <Collapse>
            {
                data.scan.results.map((result, idx) =>
                {
                    switch (result.scanner)
                    {
                        case "http":
                            return (<Collapse.Panel key={idx} header={breifHeader(result)}>
                                <HTTPResult result={result} />
                            </Collapse.Panel>);
                        case "tls":
                            return (<Collapse.Panel key={idx} header={breifHeader(result)}>
                                {<HttpsResult result={result} />}
                            </Collapse.Panel>)
                        case "ftp":
                            return (<Collapse.Panel key={idx} header={breifHeader(result)}>
                                <FTPScanResult result={result} />
                            </Collapse.Panel>);
                        case "ssh":
                            return (<Collapse.Panel key={idx} header={breifHeader(result)}>
                                <SSHResultPanel result={result} />
                            </Collapse.Panel>);
                    }
                })
            }
        </Collapse>
    </div>)
}

function breifHeader(result: NetScanResult<string, unknown>)
{
    return (<span>
        <Badge status={result.result === "Ok" ? "success" : "error"} />
        {result.scanner.toUpperCase()} {result.port} at {new Date(result.time.$date).toLocaleString()}
    </span>);
}
