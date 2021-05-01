import { DeleteOutlined } from "@ant-design/icons";
import { Button, message, Modal } from "antd";
import React, { useState } from "react";
import { API } from "../api/api";

export function ClearAllTasks()
{
    const [modalVisible, setModalVisible] = useState(false);
    const [loading, setLoading] = useState(false);
    const showModal = () =>
    {
        setModalVisible(true);
        setLoading(false);
    };
    const ok = async () =>
    {
        setLoading(true);

        try
        {
            const result = await API.scan.clearPendingTask({});
            message.success(`Removed ${result.removed_tasks} tasks`);
        }
        catch (err)
        {
            message.error(err.message);
        }
        setLoading(false);
        setModalVisible(false);
    }
    return (<>
        <Button danger size="large" icon={<DeleteOutlined />} onClick={showModal}>Clear All Tasks</Button>
        <Modal
            title="Remove All Pending Tasks"
            confirmLoading={loading}
            visible={modalVisible}
            cancelButtonProps={{ disabled: loading }}
            onOk={ok}
        >
            All pending tasks will be removed?
        </Modal>
    </>)
}