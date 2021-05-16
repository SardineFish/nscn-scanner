// Copyright (c) 2021 SardineFish
// 
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

type HTTPMethodsWithoutBody = "GET" | "HEAD" | "CONNECT" | "DELETE" | "OPTIONS";
type HTTPMethodsWithBody = "POST" | "PUT" | "PATCH";
type HTTPMethods = HTTPMethodsWithBody | HTTPMethodsWithoutBody;

type TypeNames = "number" | "string" | "boolean" | "string[]";

type TypeOfName<T> =
    T extends "number"
    ? number
    : T extends "string"
    ? string
    : T extends "boolean"
    ? boolean
    : T extends "string[]"
    ? string[]
    : never;

export type Validator<T> = (key: string, value: T) => T;

export type ParamInfo<T extends TypeNames> = T extends any ? {
    type: T,
    validator: Validator<TypeOfName<T>>,
    optional?: true,
} : never;


type OptionalParams<T extends { [key: string]: ParamInfo<TypeNames> }> = {
    [key in keyof T as T[key]["optional"] extends true ? key : never]: TypeOfName<T[key]["type"]>;
}
type RequiredParams<T extends { [key: string]: ParamInfo<TypeNames> }> = {
    [key in keyof T as T[key]["optional"] extends true ? never : key]: TypeOfName<T[key]["type"]>;
}

type ValueType<T extends ParamsDeclare> = Required<RequiredParams<T>> & Partial<OptionalParams<T>>;
// {
//     [key in keyof T]: TypeOfName<T[key]["type"]>
// }

type ParamsDeclare = {
    [key: string]: ParamInfo<TypeNames>,
}
type SimpleParamsDeclare = {
    [key: string]: ParamInfo<TypeNames> | TypeNames;
}
type FullParamsDeclare<T extends SimpleParamsDeclare> = {
    [key in keyof T]: ParamInfo<TypeNames> & (T[key] extends TypeNames ? ParamInfo<T[key]> : T[key]);
}

type ApiFunction<Path extends ParamsDeclare, Query extends ParamsDeclare, Data extends ParamsDeclare | any | undefined, Response>
    = Data extends undefined
    ? (params: ValueType<Path> & ValueType<Query>) => Promise<Response>
    : Data extends ParamsDeclare ? (params: ValueType<Path> & ValueType<Query>, body: ValueType<Data & ParamsDeclare>) => Promise<Response>
    : (params: ValueType<Path> & ValueType<Query>, body: Data) => Promise<Response>;

type UrlBuilder<Path extends ParamsDeclare, Query extends ParamsDeclare>
    = (params: ValueType<Path> & ValueType<Query>) => string;

function validateByPass<T>(_: string, value: T)
{
    return value;
}


function simpleParam<T extends SimpleParamsDeclare>(info: T): FullParamsDeclare<T>
{
    const params = {} as FullParamsDeclare<T>;
    for (const key in info)
    {
        const value = info[key];
        switch (info[key])
        {
            case "number":
                params[key] = <ParamInfo<TypeNames>>{
                    type: "number",
                    validator: validateByPass,
                } as any;
                break;
            case "string":
                params[key] = <ParamInfo<"string">>{
                    type: "string",
                    validator: validateByPass,
                } as any;
                break;
            case "boolean":
                params[key] = <ParamInfo<"boolean">>{
                    type: "boolean",
                    validator: validateByPass,
                } as any;
                break;
            case "string[]":
                params[key] = <ParamInfo<"string[]">>{
                    type: "string[]",
                    validator: validateByPass,
                } as any;
                break;
            default:
                params[key] = value as any;
        }
    }
    return params;
}

function validateNonEmpty(key: string, text: string): string
{
    if (/^\s*$/.test(text))
        throw new APIError(ClientErrorCode.InvalidParameter, `'${key}' cannot be empty`);
    return text;
}

export const Validator = {
    bypass: validateByPass,
    nonEmpty: validateNonEmpty,
}

interface ErrorResponse
{
    error: string,
}

enum ClientErrorCode
{
    Error = -1,
    InvalidParameter = -2,
    NetworkFailure = -3,
    ParseError = -4,
}

class APIError extends Error
{
    code: number;
    constructor(code: number, message: string)
    {
        super(message);
        this.code = code;
    }
}

class ApiBuilder<Method extends HTTPMethods, Path extends ParamsDeclare, Query extends ParamsDeclare, Data extends ParamsDeclare | any | undefined, Response>
{
    private method: Method;
    private url: string;
    private pathInfo: Path;
    private queryInfo: Query;
    private dataInfo: Data;
    private redirectOption?: "follow" | "error" | "manual";

    constructor(method: Method, url: string, path: Path, query: Query, data: Data)
    {
        this.method = method;
        this.url = url;
        this.pathInfo = path;
        this.queryInfo = query;
        this.dataInfo = data;
    }

    path<NewPath extends SimpleParamsDeclare>(path: NewPath)
    {
        return new ApiBuilder<Method, FullParamsDeclare<NewPath>, Query, Data, Response>(this.method, this.url, simpleParam(path), this.queryInfo, this.dataInfo);
    }
    query<NewQuery extends SimpleParamsDeclare>(query: NewQuery)
    {
        return new ApiBuilder<Method, Path, FullParamsDeclare<NewQuery>, Data, Response>(this.method, this.url, this.pathInfo, simpleParam(query), this.dataInfo);
    }
    body<T>(): ApiBuilder<Method, Path, Query, T, Response>
    body<NewData extends SimpleParamsDeclare>(data: NewData): ApiBuilder<Method, Path, Query, FullParamsDeclare<NewData>, Response>
    body<NewData extends SimpleParamsDeclare | any>(data?: NewData): ApiBuilder<Method, Path, Query, NewData extends SimpleParamsDeclare ? FullParamsDeclare<NewData> : NewData, Response>
    {
        if (this.method === "POST" || this.method === "PATCH" || this.method === "PUT")
        {
            if (!data)
                return new ApiBuilder(this.method, this.url, this.pathInfo, this.queryInfo, null as any) as any;
            return new ApiBuilder(this.method, this.url, this.pathInfo, this.queryInfo, simpleParam(data as SimpleParamsDeclare)) as any;
        }
        else
        {
            throw new APIError(ClientErrorCode.Error, `HTTP Method ${this.method} should not have body.`);
        }
    }
    redirect(redirect: "follow" | "error" | "manual")
    {
        this.redirectOption = redirect;
        return this;
    }
    urlBuilder(): UrlBuilder<Path, Query>
    {
        return (params) =>
        {
            let url = this.url;
            for (const key in this.pathInfo)
            {
                const value = (params as ValueType<Path> as any)[key];
                if (value === undefined)
                {
                    if (this.pathInfo[key].optional)
                    {
                        url = url.replace(`{${key}}`, "");
                        continue;
                    }
                    throw new APIError(ClientErrorCode.InvalidParameter, `Missing path '${key}'`);
                }
                url = url.replace(`{${key}}`, this.pathInfo[key].validator(key, value as never).toString());
            }
            const queryParams = [];
            for (const key in this.queryInfo) 
            {
                const value = (params as Partial<ValueType<Query>> as any)[key];
                if (value === undefined && !this.queryInfo[key].optional)
                    throw new APIError(ClientErrorCode.InvalidParameter, `Missing query param '${key}'`);
                else if (value !== undefined)
                    queryParams.push(`${key}=${encodeURIComponent(this.queryInfo[key].validator(key, value as never).toString())}`);
            }
            if (queryParams.length > 0)
                url = url + "?" + queryParams.join("&");
            return url;
        };
    }
    response<Response>(): ApiFunction<Path, Query, Data, Response>
    {
        const builder = new ApiBuilder<Method, Path, Query, Data, Response>(this.method, this.url, this.pathInfo, this.queryInfo, this.dataInfo);
        return builder.send.bind(builder) as ApiFunction<Path, Query, Data, Response>;
    }
    private async send(params: ValueType<Path> & ValueType<Query>, data: ValueType<Data & ParamsDeclare>): Promise<Response>
    {
        const url = this.urlBuilder()(params as ValueType<Path> & ValueType<Query>);

        if (this.dataInfo !== undefined && this.dataInfo !== null)
        {
            for (const key in this.dataInfo)
            {
                const dataInfo = (this.dataInfo as ParamsDeclare)[key];
                const value = (data as any)[key];
                if (value === undefined && !dataInfo.optional)
                    throw new APIError(ClientErrorCode.InvalidParameter, `Missing field '${key} in request body'`);
                else if (value !== undefined)
                    (data as any)[key] = dataInfo.validator(key, value as never);
            }
        }

        let response: globalThis.Response;
        try
        {
            response = await fetch(url, {
                method: this.method,
                headers: {
                    "Content-Type": "application/json",
                },
                redirect: this.redirectOption,
                body: this.dataInfo === undefined ? undefined : JSON.stringify(data as any),
            });
        }
        catch (err)
        {
            console.error(err);
            throw new APIError(ClientErrorCode.NetworkFailure, "Failed to send request.");
        }

        if (response.status >= 400)
        {
            const body = await this.parseBody<ErrorResponse>(response);
            throw new APIError(response.status, body.error);
        }

        const responseBody = await this.parseBody<Response>(response);
        return responseBody;
    }
    private async parseBody<T>(response: globalThis.Response)
    {
        try
        {
            const body = await response.json() as T;
            return body as T;
        }
        catch (err)
        {
            console.error(err);
            throw new APIError(ClientErrorCode.ParseError, "Failed to parse response body.");
        }
    }
}

export function DeclareQuery<T extends SimpleParamsDeclare>(query: T)
{
    return query;
}

export function api<Method extends HTTPMethodsWithBody>(method: Method, url: string): ApiBuilder<Method, {}, {}, {}, any>
export function api<Method extends HTTPMethodsWithoutBody>(method: Method, url: string): ApiBuilder<Method, {}, {}, undefined, any>
export function api<Method extends HTTPMethods>(method: Method, url: string): ApiBuilder<Method, {}, {}, {} | undefined, any>
{
    switch (method)
    {
        case "POST":
        case "PUT":
        case "PATCH":
            return new ApiBuilder<Method, {}, {}, {}, null>(method, url, {}, {}, {});
        default:
            return new ApiBuilder<Method, {}, {}, undefined, null>(method, url, {}, {}, undefined);
    }
}