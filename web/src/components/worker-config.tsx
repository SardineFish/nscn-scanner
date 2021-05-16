import { CopyFilled, SettingOutlined } from "@ant-design/icons";
import { Button, Checkbox, Col, Divider, InputNumber, message, Modal, Row, Slider, Space, Switch } from "antd";
import Text from "antd/lib/typography/Text";
import React, { useEffect, useState } from "react";
import { API, WorkerConfig } from "../api/api";

function useRefresh()
{
    const [_, setRefresh] = useState({});
    return () => setRefresh({});
}

export function WorkerConfig(props: { workerAddr: string })
{
    const [config, setConfig] = useState<WorkerConfig | null>(null);
    const [modalVisible, setModalVisible] = useState(false);
    const [loading, setLoading] = useState(false);
    const update = useRefresh();

    useEffect(() =>
    {
        (async () =>
        {
            const config = await API.scheduler.getWorkerConfig({ worker: props.workerAddr });
            setConfig(config);
        })();
    }, [props.workerAddr]);
    const showModal = () =>
    {
        if (!config)
        {
            message.warn(`Woker '${props.workerAddr}' is not running`);
            return;
        }
        setModalVisible(true);
        setLoading(false);
    };
    const ok = async () =>
    {
        if (!config)
        {
            message.warn(`Woker '${props.workerAddr}' is not running`);
            return;
        }
        setLoading(true);
        await API.scheduler.setupWorkerConfig({ worker: props.workerAddr }, config);
        setModalVisible(false);
        setLoading(false);
    };
    if (config)
    {
        return (<>
            <Button type="text" icon={<SettingOutlined />} onClick={showModal} />
            <Modal
                visible={modalVisible}
                title={`Worker-${props.workerAddr} Settings`}
                confirmLoading={loading}
                cancelButtonProps={{ disabled: loading }}
                onOk={ok}
                onCancel={() => setModalVisible(false)}
                style={{userSelect: "none"}}
            >
                <Row gutter={[0, 16]}>
                    <Col span={24}>
                        <Space direction="horizontal" size="large">
                            <Space>
                                <Text strong>Net Scanner: </Text>
                                <Switch
                                    checked={config.scanner.scheduler.enabled}
                                    checkedChildren="On"
                                    unCheckedChildren="Off"
                                    onChange={v => { config.scanner.scheduler.enabled = v, update() }}
                                />
                            </Space>
                            <Space>
                                <Checkbox defaultChecked={true}>Use Proxy</Checkbox>
                            </Space>
                        </Space>
                    </Col>
                    <Col span={24}>
                        <Space direction="horizontal">
                            <Checkbox
                                checked={config.scanner.http.enabled}
                                disabled={!config.scanner.scheduler.enabled}
                                onChange={p => { config.scanner.http.enabled = p.target.checked, update() }}
                            >HTTP</Checkbox>
                            <Checkbox
                                checked={config.scanner.https.enabled}
                                disabled={!config.scanner.scheduler.enabled}
                                onChange={p => { config.scanner.https.enabled = p.target.checked, update() }}
                            >HTTPS</Checkbox>
                            <Checkbox
                                checked={config.scanner.ftp.enabled}
                                disabled={!config.scanner.scheduler.enabled}
                                onChange={p => { config.scanner.ftp.enabled = p.target.checked, update() }}
                            >FTP</Checkbox>
                            <Checkbox
                                checked={config.scanner.ssh.enabled}
                                disabled={!config.scanner.scheduler.enabled}
                                onChange={p => { config.scanner.ssh.enabled = p.target.checked, update() }}
                            >SSH</Checkbox>
                        </Space>
                    </Col>
                    <Col span={24}>
                        <Row gutter={16}>
                            <Col style={{ display: "flex", alignItems: "center"}}>
                                <header>Max Tasks</header>
                            </Col>
                            <Col flex={1}>
                                <Slider
                                    min={0}
                                    max={6000}
                                    value={config.scanner.scheduler.max_tasks}
                                    disabled={!config.scanner.scheduler.enabled}
                                    onChange={(v: number) => { config.scanner.scheduler.max_tasks = v, update() }}
                                />
                            </Col>
                            <Col>
                                <InputNumber
                                    disabled={!config.scanner.scheduler.enabled}
                                    value={config.scanner.scheduler.max_tasks}
                                    onChange={v => { config.scanner.scheduler.max_tasks = v, update() }}
                                />
                            </Col>
                        </Row>
                    </Col>
                    <Col span={24}>
                        <Space direction="horizontal">
                            
                        </Space>
                    </Col>

                    <Col span={24}>
                        <Space>
                            <Text strong>Service Analyser: </Text>
                            <Switch
                                checked={config.analyser.scheduler.enabled}
                                checkedChildren="On"
                                unCheckedChildren="Off"
                                onChange={v => { config.analyser.scheduler.enabled = v, update() }}
                            />
                        </Space>
                    </Col>
                    <Col span={24}>
                        <Row gutter={16}>
                            <Col style={{ display: "flex", alignItems: "center" }}>
                                <header>Max Tasks</header>
                            </Col>
                            <Col flex={1}>
                                <Slider
                                    min={0}
                                    max={64}
                                    value={config.analyser.scheduler.max_tasks}
                                    disabled={!config.analyser.scheduler.enabled}
                                    onChange={(v: number) => { config.analyser.scheduler.max_tasks = v, update() }}
                                />
                            </Col>
                            <Col>
                                <InputNumber
                                    disabled={!config.analyser.scheduler.enabled}
                                    min={0}
                                    max={64}
                                    value={config.analyser.scheduler.max_tasks}
                                    onChange={v => { config.analyser.scheduler.max_tasks = v, update() }}
                                />
                            </Col>
                        </Row>
                    </Col>
                    <Col span={24}>
                        <Space direction="horizontal">

                        </Space>
                    </Col>
                </Row>
                
            </Modal>
        </>)
    }
    return null;
}