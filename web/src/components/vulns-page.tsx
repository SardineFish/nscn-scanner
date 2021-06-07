
import { WarningOutlined, WarningTwoTone } from "@ant-design/icons";
import { Collapse, Descriptions, Divider, Empty, List, Tag } from "antd";
import Text from "antd/lib/typography/Text";
import React from "react";
import { ScanResult } from "../api/api";

export function VulnsPage(props: {result: ScanResult})
{
    const data = props.result;
    if (!data.vulns || !data.analyse)
    {
        return null;
    }
    const services = data.analyse.services;
    const totalVulns = Object.keys(services).map(key => services[key].vulns.length).reduce((a, v) => v + a, 0);
    const vulns = data.vulns;
    return (<div className="vulns-page">
        <Divider orientation="left">Services</Divider>
        {Object.keys(services).length === 0
            ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
            : <Descriptions column={2}>
                {Object.keys(services).map((key, idx) => (
                    <Descriptions.Item key={idx} label={services[key].name}>
                        {services[key].version || "unknown"}
                        <br />
                        {services[key].vulns.length > 0
                            ? <Tag className="vuln-count" color="warning" icon={<WarningOutlined />}>{services[key].vulns.length}</Tag>
                            : null
                        }
                    </Descriptions.Item>
                ))}
            </Descriptions>
        }
        
        <Divider orientation="left">Vulnerabilities</Divider>
        {totalVulns > 0
            ? <Collapse>
                {Object.keys(services).filter(key => services[key].vulns.length > 0)
                    .map((key, idx) => (
                        <Collapse.Panel key={idx} header={services[key].name + " " + services[key].version}>
                            <List className="vuln-list" size="small">
                                {services[key].vulns.map((vuln, idx) => (
                                    <List.Item key={idx}>
                                        <Text className="vuln-id" strong>{vulns[vuln].id}</Text>
                                        <a className="vuln-title" href={vulns[vuln].url}>{vulns[vuln].title}</a>
                                    </List.Item>
                                ))}
                            </List>
                        </Collapse.Panel>
                    ))}
            </Collapse>
            : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
        }
        
    </div>)
}