import React from "react";
import { Col, Divider, Row, Space } from "antd";
import { RealtimeResultPanel } from "../components/realtime-result";
import { SchedulerStatsPanel } from "../components/scheduler-stats";
import { SysStats } from "../components/sys-stats";
import { TaskQueuePanel } from "../components/task-queue";


export const TaskPage: React.FC = () =>
{
    return (<main className="task-page">
        <Space direction="vertical" size={30}>
            <SysStats />
            <Divider orientation="left">Scheduler Status</Divider>
            <SchedulerStatsPanel />
            <Row gutter={30}>
                <Col span={12}>
                    <TaskQueuePanel />
                </Col>
                <Col span={12}>
                    <RealtimeResultPanel />
                </Col>
            </Row>
        </Space>
    </main>)
};