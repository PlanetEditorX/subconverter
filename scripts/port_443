/**
 * 修改所有节点端口为 443
 * 用法：Sub-Store 添加脚本，自动处理订阅内容
 */

const inArg = $arguments;

function operator(proxies) {
  proxies.forEach(proxy => {
    if (proxy.port && typeof proxy.port === 'number') {
      proxy.port = 443;
    }
  });
  return proxies;
}
