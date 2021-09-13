function start(bufferSize=5242880, checkSize=1038336) {
    document.getElementById("result").innerText = "Status: running"

    var ws = new WebSocket("ws://"+location.hostname+":12345");

    ws.onopen = function (evt) {
        console.log("Connection open");
        ws.send("test");
        console.log("connect ok");
        setTimeout(calc, 1000, ws, bufferSize, checkSize);
    };
    ws.onclose = function (evt) {
        console.log("Connection closed");
    };
    return false;
}

function calc(ws, bufferSize, checkSize) {
    var data = new ArrayBuffer(bufferSize);
    ws.send(data);
    var n = 1;
    var interval = setInterval(function () {
        console.log("all", bufferSize, "bufferedAmount", ws.bufferedAmount, "sended", bufferSize - ws.bufferedAmount)
        if (n === 5) {
            if ((bufferSize - ws.bufferedAmount) > checkSize) {
                document.getElementById("result").innerText = "Status: found proxy"
            } else {
                document.getElementById("result").innerText = "Status: no proxy"
            }
            clearInterval(interval);
        }
        n = n + 1;
    }, 100);
}

if (document.readyState == 'loading') {
    document.addEventListener('DOMContentLoaded', function () {start()});
} else {
    start();
}