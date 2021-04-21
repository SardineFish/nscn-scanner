
import { WarningOutlined, WarningTwoTone } from "@ant-design/icons";
import { Collapse, Descriptions, Divider, Empty, List, Tag } from "antd";
import Text from "antd/lib/typography/Text";
import React from "react";
import { ScanResult } from "../api/api";

export function VulnsPage(props: {result: ScanResult})
{
    const data = props.result;
    const vulns = Object.keys(data.services).map(key => data.services[key].vulns.length).reduce((a, v) => v + a, 0);
    return (<div className="vulns-page">
        <Descriptions title="Services" column={2}>
            {Object.keys(data.services).map((key, idx) => (
                <Descriptions.Item key={idx} label={data.services[key].name}>
                    {data.services[key].version || "unknown"}
                    <br />
                    {data.services[key].vulns.length > 0
                        ? <Tag className="vuln-count" color="warning" icon={<WarningOutlined />}>{data.services[key].vulns.length}</Tag>
                        : null
                    }
                </Descriptions.Item>
            ))}
        </Descriptions>
        <Divider orientation="left">Vulnerabilities</Divider>
        {vulns > 0
            ? <Collapse>
                {Object.keys(data.services).filter(key => data.services[key].vulns.length > 0)
                    .map((key, idx) => (
                        <Collapse.Panel key={idx} header={data.services[key].name + " " + data.services[key].version}>
                            <List className="vuln-list" size="small">
                                {data.services[key].vulns.map((vuln, idx) => (
                                    <List.Item>
                                        <Text className="vuln-id" strong>{vuln.id}</Text>
                                        <a className="vuln-title" href={vuln.url}>{vuln.title}</a>
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