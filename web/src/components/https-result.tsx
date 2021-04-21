import React from "react";
import { ScanResult } from "../api/api";
import { ArrayElement, extract, parsePEM } from "../utils/utils";
import { GenericScanResult } from "./generic-scan-result";
import {Buffer} from "buffer";
import { Descriptions, Divider, message } from "antd";
import * as asn1js from "asn1js";
// import Certificate from "pkijs/src/Certificate";
import { Attribute, Certificate } from "@sardinefish/x509";

export function HttpsResult(props: { result: ArrayElement<ScanResult["https_results"]> })
{
    const data = props.result;
    if (data.result === "Ok")
    {
    //     let cert: Certificate = null as any;
    //     const pem = parsePEM(data.data.cert);
    //     console.log(pem);
    //     cert = new Certificate({ schema: asn1js.fromBER(new Uint8Array(pem).buffer).result });
    //     console.log(cert);
        const cert = Certificate.fromPEM(Buffer.from(data.data.cert, "utf-8"));
        console.log(cert);
        return (<>
            <GenericScanResult result={props.result} scanner="TLSScanner"/>
            <Divider orientation="left">Certificate</Divider>
            <Descriptions column={2} size="small" bordered>
                <Descriptions.Item label="Valid From">{cert.validFrom.toLocaleString()}</Descriptions.Item>
                <Descriptions.Item label="Valid To">{cert.validTo.toLocaleString()}</Descriptions.Item>
                <Descriptions.Item label="Key Usage">{cert.keyUsage}</Descriptions.Item>
                <Descriptions.Item label="Email Addresses">{cert.emailAddresses.join(", ")}</Descriptions.Item>
                <Descriptions.Item label="URIs">{cert.uris.join(", ")}</Descriptions.Item>
                <Descriptions.Item label="Version">{cert.version}</Descriptions.Item>
                <Descriptions.Item label="DNS Names" span={2}>{cert.dnsNames.join(", ")}</Descriptions.Item>
                {/* <Descriptions.Item label="Subject Key Identifier" span={2}>{cert.subjectKeyIdentifier}</Descriptions.Item>
                <Descriptions.Item label="Authority Key Identifier" span={2}>{cert.authorityKeyIdentifier}</Descriptions.Item>
                <Descriptions.Item label="Subject Key Identifier" span={2}>{cert.subjectKeyIdentifier}</Descriptions.Item> */}
                <Descriptions.Item label="OCSP Server">{cert.ocspServer}</Descriptions.Item>
                <Descriptions.Item label="Is CA">{cert.isCA}</Descriptions.Item>
                <Descriptions.Item label="Pubkey Algorithm">{cert.publicKey.algo}</Descriptions.Item>
                <Descriptions.Item label="Signature Algorithm">{cert.signatureAlgorithm}</Descriptions.Item>

                {showAttributes(cert.subject.attributes, "Subject")}
                {showAttributes(cert.issuer.attributes, "Issuer")}
                {showAttributes}


            </Descriptions>
        </>)
    }
    else
    {
        return (<>
            <GenericScanResult result={props.result} scanner="TLSScanner"/>
            <Divider orientation="left">Error Message</Divider>
            <p>{data.data}</p>
        </>)
    }
}

const rdnmap = {
    "2.5.4.6": "CountryName",
    "2.5.4.10": "Organization",
    "2.5.4.11": "OrganizationalUnit",
    "2.5.4.3": "CommonName",
    "2.5.4.7": "Locality",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.12": "Title",
    "2.5.4.42": "GivenName",
    "2.5.4.43": "I",
    "2.5.4.4": "SurName",
    "1.2.840.113549.1.9.1": "E-mail"
};

function firstCaseUpper(text: string): string
{
    text = text.replace(/[A-Z]/g, (str) => " " + str.toUpperCase());
    return (text.substr(0, 1).toUpperCase() + text.substr(1));
}

function showAttributes(attributes: Attribute[], key: string)
{
    return [
        <Descriptions.Item span={2} label={key} key={key}>{ }</Descriptions.Item>,
        ...attributes.map((attr, idx) =>
        (
            <Descriptions.Item label={firstCaseUpper(attr.name)} key={key + idx}>{attr.value}</Descriptions.Item>
        ))];
}