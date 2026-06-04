/**
 * replace-host.js
 *
 * 用法:
 * #host=aaa.bbb.ccc
 *
 * 将所有 localhost 替换为指定域名
 */

let inArg = {};

try {
    if ($arguments) {
        inArg = $arguments;
        console.log("Arguments:", inArg);
    }
} catch (e) {
    console.log("$arguments not defined");
}

function replaceLocalhost(obj, domain) {
    if (!obj || typeof obj !== "object") {
        return;
    }

    Object.keys(obj).forEach(key => {
        const value = obj[key];

        // 字符串
        if (typeof value === "string") {
            if (value === "localhost") {
                obj[key] = domain;
            }
        }

        // 数组
        else if (Array.isArray(value)) {
            value.forEach(item => {
                if (typeof item === "object") {
                    replaceLocalhost(item, domain);
                }
            });
        }

        // 对象
        else if (typeof value === "object") {
            replaceLocalhost(value, domain);
        }
    });
}

function operator(proxies) {

    const host = inArg.host;

    if (!host) {
        console.log("未提供 host 参数");
        return proxies;
    }

    console.log(`开始替换 localhost -> ${host}`);

    let count = 0;

    proxies.forEach(proxy => {

        const before = JSON.stringify(proxy);

        replaceLocalhost(proxy, host);

        const after = JSON.stringify(proxy);

        if (before !== after) {
            count++;
            console.log(`已修改节点: ${proxy.name}`);
        }
    });

    console.log(`完成，共修改 ${count} 个节点`);

    return proxies;
}
