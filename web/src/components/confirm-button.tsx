import { DeleteOutlined } from "@ant-design/icons";
import { Button, ButtonProps, message, Modal } from "antd";
import React, { useState } from "react";
import { API } from "../api/api";

export function ConfirmButton(props: {children: React.ReactNode, onOk:()=>Promise<any>, buttonProps?: Partial<ButtonProps>, title?:string, confirmText: string})
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
        
        await props.onOk();

        
        setLoading(false);
        setModalVisible(false);
    }
    
    return (<>
        <Button onClick={showModal} {...props.buttonProps}>{props.children}</Button>
        <Modal
            title={props.title}
            confirmLoading={loading}
            visible={modalVisible}
            cancelButtonProps={{ disabled: loading }}
            onOk={ok}
            onCancel={()=>setModalVisible(false)}
        >
            {props.confirmText}
        </Modal>
    </>)
}