import { Divider } from "antd";
import React from "react";
import { SchedulerStatsPanel } from "../components/scheduler-stats";
import { SysStats } from "../components/sys-stats";


export const TaskPage: React.FC = () =>
{
    return (<main className="task-page">
        <SysStats />
        <Divider orientation="left">Scheduler Status</Divider>
        <SchedulerStatsPanel />
    </main>)
};