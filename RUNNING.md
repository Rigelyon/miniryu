# SDN Controller + Flask Dashboard Run Guide

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

If Mininet is not installed yet (Ubuntu/Linux usually):

```bash
sudo apt-get install mininet
```

## 2. Run Ryu Controller

From project root:

```bash
ryu-manager main.py --wsapi-port 8080
```

Ryu REST endpoints exposed by this project:

- `GET /api/status`
- `GET /api/attacks`
- `POST /api/block_ip`
- `POST /api/load_balancer/enable`
- `POST /api/load_balancer/disable`

## 3. Run Mininet Topology

Example with OpenFlow 1.3 switch:

```bash
sudo mn --topo single,3 --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13
```

For OpenFlow 1.0 testing:

```bash
sudo mn --topo single,3 --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow10
```

## 4. Run Flask Dashboard

In a new terminal from project root:

```bash
set RYU_API_URL=http://127.0.0.1:8080/api
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=admin
python -m web.app
```

Open dashboard at:

- `http://127.0.0.1:5000/login`

## 5. Flask Dashboard APIs

These are provided by Flask (proxying to Ryu where needed):

- `GET /network/status`
- `GET /attacks`
- `POST /block_ip`
- `POST /enable_load_balancer`
- `POST /disable_load_balancer`

## Notes

- Default load balancer VIP is `10.0.0.100`.
- Default backend server placeholders are `10.0.0.2` and `10.0.0.3` with ports `2` and `3`.
- For production, change Flask secret key and admin credentials.
