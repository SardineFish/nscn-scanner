import React, { useEffect, useState } from "react";
import { Col, Layout, Row, Statistic } from "antd";
import { StatsPreview } from "../components/stats-preview";

export const HomePage: React.FC = () =>
{

    return (
        <Layout>
            <Layout.Header>Header</Layout.Header>
            <Layout.Content>
                <StatsPreview />
            </Layout.Content>
            <Layout.Footer>Footer</Layout.Footer>
        </Layout>
    )
};