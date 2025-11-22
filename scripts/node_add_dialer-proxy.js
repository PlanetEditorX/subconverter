/**
 * 给所有节点添加 dialer-proxy 字段
 * 用法：Sub-Store 添加脚本，自动处理订阅内容
 */

const inArg = $arguments;

function operator(proxies) {
  proxies.forEach(proxy => {
    // 给所有节点加上 dialer-proxy
    proxy['dialer-proxy'] = '🏆 优选节点';

    // 如果只想给特定节点加，可以用名字过滤
    // if (/VPS|落地/.test(proxy.name)) {
    //   proxy['dialer-proxy'] = '机场节点';
    // }
  });
  return proxies;
}
