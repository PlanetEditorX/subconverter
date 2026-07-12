// @name 全局字符串替换
// @description 全局替换节点中的字符串
// @argument oldString 替换前字符串
// @argument newString 替换后字符串

const oldString = $arguments.oldString || "";
const newString = $arguments.newString || "";

if (!oldString) {
    console.log("oldString 参数为空");
    return proxies;
}

function replaceAll(obj) {
    if (typeof obj === "string") {
        return obj.replaceAll(oldString, newString);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => replaceAll(item));
    }

    if (obj && typeof obj === "object") {
        for (const key in obj) {
            obj[key] = replaceAll(obj[key]);
        }
    }

    return obj;
}


return replaceAll(proxies);
