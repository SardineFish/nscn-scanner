import { Drawer, Menu, PageHeader } from "antd";
import React, { useEffect, useState } from "react";

export function ScanResultDetail(props: { addr: string, visible: boolean, onClose: () => void })
{
    const [page, setPage] = useState("overview");
    const [data, setData] = useState(null);
    useEffect(() =>
    {
        setPage("overview");
        (async () =>
        {
            
        });
    }, [props.addr]);
    return (<>
        <Drawer
            className="result-detail" 
            visible={props.visible}
            width={800}
            onClose={props.onClose}
            title={(<>
                <PageHeader title={props.addr}></PageHeader>
                <Menu mode="horizontal" selectedKeys={[page]} onSelect={(props)=>setPage(props.key as string)}>
                    <Menu.Item key="overview">Overview</Menu.Item>
                    <Menu.Item key="scan">Scanning</Menu.Item>
                    <Menu.Item key="vulns">Vulnerabilities</Menu.Item>
                </Menu>
            </>)}
        >

        </Drawer>
    </>)
}