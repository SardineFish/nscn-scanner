import { Badge, Carousel, Collapse, Descriptions, Divider, Drawer, Menu, PageHeader } from "antd";
import { CarouselRef } from "antd/lib/carousel";
import React, { useEffect, useRef, useState } from "react";
import { API, NetScanResult, ScanResult } from "../api/api";
import { HttpsResult } from "./https-result";
import { HTTPResult } from "./http-result";
import { FTPScanResult } from "./ftp-result";
import { SSHResultPanel } from "./ssh-result";

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
                    <Menu.Item key={1}>Scanning</Menu.Item>
                    <Menu.Item key={2}>Vulnerabilities</Menu.Item>
                </Menu>
            </>)}
        >
            {
                data
                    ?
                    <Carousel ref={ref}>
                        <Overview data={data} />
                        <ScanningResults data={data}/>
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
            <Descriptions.Item label="IP">{data.addr}</Descriptions.Item>
            <Descriptions.Item label="Status">{
                data.opened_ports.length > 0
                    ? <Badge status="success" text="Online"/>
                    : <Badge status="default" text="Offline"/>
            }</Descriptions.Item>
            <Descriptions.Item label="Last Update">{new Date(data.last_update).toLocaleString()}</Descriptions.Item>
            <Descriptions.Item label="Opened Ports">{
                data.opened_ports.length > 0
                    ? data.opened_ports.join(", ")
                    : "None"
            }</Descriptions.Item>
        </Descriptions>
    </div>)
}
type ArrayElement<ArrayType extends readonly unknown[]> =
    ArrayType extends readonly (infer ElementType)[] ? ElementType : never;

function ScanningResults(props: { data: ScanResult })
{
    const data = props.data;
    return (<div className="results">
        <Collapse>
            {data.http_results.map((data, idx) => (
                <Collapse.Panel key={"http" + idx} header={breifHeader("HTTP", 80, data)}>
                    <HTTPResult result={data} />
                </Collapse.Panel>
            ))}
            {data.https_results.map((data, idx) => (
                <Collapse.Panel key={"https"+idx} header={breifHeader("HTTPS", 443, data)}>
                    {<HttpsResult result={data}/>}
                </Collapse.Panel>))}
            {data.ftp_results.map((data, idx) => (
                <Collapse.Panel key={"ftp" + idx} header={breifHeader("FTP", 21, data)}>
                    <FTPScanResult result={data}/>
                </Collapse.Panel>
            ))}
            {data.ssh_results.map((data, idx) => (
                <Collapse.Panel key={"ssh" + idx} header={breifHeader("SSH", 22, data)}>
                    <SSHResultPanel result={data}/>
                </Collapse.Panel>
            ))}
        </Collapse>
    </div>)
}

function breifHeader(name: string, port: number, data: NetScanResult<any>)
{
    return (<span>
        <Badge status={data.result === "Ok" ? "success" : "error"} />
        {name} {port} at {new Date(data.time.$date).toLocaleString()}
    </span>);
}
