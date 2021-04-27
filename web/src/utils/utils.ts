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

export function formatbytes(bytes: number, fractionDigits?: number)
{
    if (bytes === 0)
        return "0B";
    if (isNaN(bytes) || bytes === undefined || bytes === null)
        return "NaN";
    let exponent = Math.floor(Math.log2(bytes) / 10);
    const units = ['', 'K', 'M', 'G', 'T', 'P'];
    return (bytes / (2 ** (exponent * 10)))
        .toLocaleString(undefined, {
            maximumFractionDigits: fractionDigits
        }) + units[exponent] + "B";
}