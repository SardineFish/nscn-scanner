import { PlusOutlined, UploadOutlined } from "@ant-design/icons";
import { Button, message, Modal, Upload } from "antd";
import TextArea, { TextAreaRef } from "antd/lib/input/TextArea";
import Text from "antd/lib/typography/Text";
import { RcFile } from "antd/lib/upload";
import Dragger from "antd/lib/upload/Dragger";
import React, { ChangeEvent, ChangeEventHandler, useRef, useState } from "react";
import { API } from "../api/api";

export function NewScanTask()
{
    const [modalVisible, setModalVisible] = useState(false);
    const [loading, setLoading] = useState(false);
    const [text, setText] = useState("");

    const ok = async () =>
    {
        setLoading(true);
        const urls = [] as string[];
        const ipRanges = [] as string[];
        const items = text.split(/\r|\n/);
        for (const item of items)
        {
            if (/^\s*$/.test(item))
                continue;
            if (/^(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(?:\/(\d+))?$/.test(item))
                ipRanges.push(item);
            else
                urls.push(item);
        }

        try
        {
            const result = await API.scan.requestScanIpList({}, {
                addr_ranges: ipRanges,
                fetch_urls: urls,
            });
            message.success(`Enqueued totally ${result.tasks} IPs to scan.`);

            setLoading(false);
            setModalVisible(false);
            setText("");
        }
        catch (err)
        {
            message.error(err.message);
            setLoading(false);
        }
    };
    const cancel = () =>
    {
        setModalVisible(false);
    };
    const onChange = (ev: ChangeEvent<HTMLTextAreaElement>) =>
    {
        setText(ev.target.value);
    };
    const upload = async (file: RcFile, files: RcFile[]) =>
    {
        setLoading(true);
        const text = (await Promise.all(files.map(f => f.text()))).join("\r\n");
        setText(text);
        return false;
    };

    return (<>
        <Button type="primary" size="large" icon={<PlusOutlined />} onClick={()=>setModalVisible(true)}>New Scan Task</Button>
        <Modal
            title="New Scanning Task"
            visible={modalVisible}
            onOk={ok}
            onCancel={cancel}
            confirmLoading={loading}
            cancelButtonProps={{ disabled: loading }}
            footer={[
                <Button key="back" onClick={() => setModalVisible(false)}>Cancel</Button>,
                <Upload key="upload" beforeUpload={upload} style={{display: "inline-block"}} showUploadList={false}>
                    <Button icon={<UploadOutlined />}>Upload</Button>
                </Upload>,
                <Button key="submit" type="primary" onClick={ok}>Dispatch</Button>,
            ]}
        >
            <Dragger
                className="task-upload-dragger"
                beforeUpload={upload}
                multiple={true}
                openFileDialogOnClick={false}
                showUploadList={false}
            >
                <div className="drag-hint">
                    <UploadOutlined size={32}/>
                    <Text>Drop to Upload</Text>
                </div>
                <TextArea
                    rows={12}
                    value={text}
                    onChange={onChange}
                    placeholder={`# Input IP ranges to be scaned.
e.g.
10.1.0.0/16
192.168.1.0/24

# Or URLs to fetch an address list.
e.g.
https://raw.githubusercontent.com/metowolf/iplist/master/data/cncity/420100.txt

`}
                />
            </Dragger>
        </Modal>
    </>);
}