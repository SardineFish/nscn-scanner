import React, { useState } from "react";
import { Card, List, Spin } from "antd";
import InfiniteScroll from "react-infinite-scroller";
import { API } from "../api/api";

export function TaskQueuePanel()
{
    const [tasks, setTasks] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);
    const [hasMore, setHasMore] = useState(true);
    const [skip, setSkip] = useState(0);

    const loadMore = async () =>
    {
        setLoading(true);
        const fetchedTasks = await API.scan.getPendingTask({ skip, count: 10 });
        setTasks([...tasks, ...fetchedTasks]);
        if (fetchedTasks.length <= 0)
            setHasMore(false);
        setSkip(skip + fetchedTasks.length);
        setLoading(false);
    }

    return (<Card title="Pending Task Queue">
        <InfiniteScroll className="task-queue-list" hasMore={!loading && hasMore} loadMore={loadMore}>
            <List
                dataSource={tasks}
                itemLayout="vertical"
                renderItem={(task, idx) => (<List.Item key={idx}>{task}</List.Item>)}
            />
            {
                loading ? <Spin /> : null
            }

        </InfiniteScroll>
    </Card>)
}