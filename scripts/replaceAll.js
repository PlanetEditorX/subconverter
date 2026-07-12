// @name 全局字符串替换
// @description 通过参数动态替换订阅内容中的字符串
// @argument oldString 替换前字符串
// @argument newString 替换后字符串

const oldString = $arguments.oldString || "";
const newString = $arguments.newString || "";

if (!oldString) {
    console.log("未设置 oldString 参数");
    return;
}

function replaceAll(obj) {
    if (typeof obj === "string") {
        return obj.replaceAll(oldString, newString);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => replaceAll(item));
    }

    if (obj !== null && typeof obj === "object") {
        const result = {};

        for (const key in obj) {
            result[key] = replaceAll(obj[key]);
        }

        return result;
    }

    return obj;
}

$content = replaceAll($content);
