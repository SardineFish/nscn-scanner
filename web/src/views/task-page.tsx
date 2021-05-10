import React, { useEffect, useState } from "react";
import { Col, Divider, Row, Space } from "antd";
import { RealtimeResultPanel } from "../components/realtime-result";
import { SchedulerStatsPanel } from "../components/scheduler-stats";
import { WorkerStats } from "../components/worker-stats";
import { TaskQueuePanel } from "../components/task-queue";
import { API } from "../api/api";


export const TaskPage: React.FC = () =>
{
    const [workers, setWorkers] = useState<string[]>([]);
    useEffect(() =>
    {
        (async () =>
        {
            let workers = await API.scheduler.getWorkers({});
            setWorkers(workers);
        })();
    }, []);
    return (<main className="task-page">
        <Space direction="vertical" size={30}>
            <SchedulerStatsPanel />
            <Row gutter={30}>
                <Col span={18}>
                    <Divider orientation="left">Workers Stats</Divider>
                    {workers.map((worker, idx) => (<WorkerStats worker={worker} key={idx}/>))}
                </Col>
                <Col span={6}>
                    <TaskQueuePanel />
                </Col>
            </Row>
        </Space>
    </main>)
};