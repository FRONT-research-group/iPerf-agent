# iPerf-agent for mptcp

* docker run -p 5000:5000 -p 5001:5001/tcp -p 5001:5001/udp p4lik4ri/iperf-app:mptcp

## Example curl request for server: 
```
 curl -X POST -H "Content-Type: application/json" http://<server-ip>:5000/Iperf -d '{ "-i": 1, "-t": "30","-s": ""}'
```

## Example curl request for client: 
```
curl -X POST -H "Content-Type: application/json" http://<client-ip>:5000/Iperf -d '{ "-b": "5M", "-i": 1, "-t": "15", "-c": "<server-ip>"}'
```

## Retrieve Results
```
curl <server-ip>:5000/LastJsonResult
```

### Arguments that can be passed

        "--bandwidth": "-b",
        "--bind": "-B",
        "--client": "-c",  # for iPerf Server
        "--compatibility": "-C",
        "--dualtest": "-d",
        "--format": "-f",
        "--interval": "-i",
        "--len": "-l",
        "--listenport": "-L",
        "--print_mss": "-m",
        "--mss": "-M",
        "--num": "-n",
        "--nodelay": "-N",
        "--port": "-p",
        "--tradeoff": "-r",
        "--tos": "-S",
        "--time": "-t",
        "--ttl": "-T",
        "--udp": "-u",
        "--window": "-w"