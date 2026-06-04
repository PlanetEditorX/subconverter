/**
 * 用法:
 * replace-host.js#host=aaa.bbb.ccc
 *
 * 将节点中的 localhost 替换为指定域名
 */

let inArg = {};

try {
    if ($arguments) {
        inArg = $arguments;
    }
} catch (e) {}

const HOST = inArg.host || "";

if (!HOST) {
    console.log("未传入 host 参数");
    return $proxies;
}

console.log(`替换 localhost -> ${HOST}`);

function replaceValue(obj) {
    if (!obj || typeof obj !== "object") return;

    for (const key in obj) {
        const value = obj[key];

        if (typeof value === "string") {
            if (value === "localhost") {
                obj[key] = HOST;
            }
        } else if (typeof value === "object") {
            replaceValue(value);
        }
    }
}

$proxies.forEach(proxy => {
    replaceValue(proxy);
});

return $proxies;
