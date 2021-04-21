import { Buffer } from "buffer";

export type ArrayElement<ArrayType extends readonly unknown[]> =
    ArrayType extends readonly (infer ElementType)[] ? ElementType : never;

export function extract<T, K extends keyof T>(obj: T, keys: K[]): {[key in K]: T[key]}
{
    const result = {} as any;

    for (const key in obj)
    {
        result[key] = obj[key];
    }
    return result;
}

export function parsePEM(pem: string)
{
    let base64 = pem
        .replace(/-{5}(BEGIN|END) CERTIFICATE-{5}/g, "")
        .replace(/[\r\n ]/g, "");
    const raw = Buffer.from(base64, "base64");
    return raw;
}