import os
import json
import subprocess
import signal
import base64
import zipfile
import hashlib
import requests
import sys
import os
import pickle
import re
import bz2
import operator
import uuid
import multiprocessing
import json
from TS import *

from operator import itemgetter
from flask import Flask, jsonify, request
app = Flask(__name__)

LOCARD_SERVER = <server_url>
BASEDIR= <BASEDIRPATH>
USER=<Locard user name>
PASSWORD=<Locard user password>
RUNNING = []
WORKDIR = os.path.join(BASEDIR, 'workdir')
MODELDIR = os.path.join(BASEDIR, 'models')
RESFN = "results.json"
DATACSVFN = "data.csv"
DATAPCPFN = "data.pcap"
TRAINCSVFN = "train_data.csv"
DATANFN = "norm"
DATASFN = "stream"
TDATADIR = "data"

run_train = {}
run_predict = {}

@app.route('/')
def index():
  return 'Server Works!'

@app.route('/greet')
def say_hello():
  return 'Hello from Server'

@app.route('/runningp')
def runningp():
  ret = {}
  running = []
  done = []
  for wd, p in run_predict.items():
    if p.is_alive():
      print("STILL RUNNING: %s" % wd)
      running.append(wd)
    else:
      done.append(wd)
  ret["running"] = running
  ret["done"] = done
  return jsonify(ret)


@app.route('/runningt')
def runningt():
  ret = {}
  running = []
  done = []
  for wd, p in run_train.items():
    if p.is_alive():
      print("STILL RUNNING: %s" % wd)
      running.append(wd)
    else:
      done.append(wd)
  ret["running"] = running
  ret["done"] = done
  return jsonify(ret)

@app.route('/models')
def models():
  ret = {}
  models = []
  for root, dirs, files in os.walk(MODELDIR):
    for f in files:
      if f.endswith(".mdl"):
        #models.append(os.path.join(root, f))
        models.append(os.path.splitext(f)[0])
  ret["models"] = models
  return jsonify(ret)

def zipdir(path, ziph):
  # ziph is zipfile handle
  for root, dirs, files in os.walk(path):
    for file in files:
      if file == RESFN:
        ziph.write(os.path.join(root, file),
            os.path.relpath(os.path.join(root, file),
              os.path.join(path, '..')))


def mk_ev_str(ev):
  ret = "{\r\n    "
  ret += "\"caseId\":\"" + ev['caseId'] + "\"\r\n    "
  ret += "\"hash\":\""+ ev['hash'] + "\"\r\n    "
  ret += "\"filename\":\"" + ev['filename'] + "\"\r\n    "
  ret += "\"content\":\"" + ev['content'] + "\"\r\n    "
  ret += "}"
  return ret

def send_evidence(caseid, invid, case_uuid, case_workdir):
  wd = "_".join([caseid, invid, case_uuid])
  wd_path = case_workdir # os.path.join(WORKDIR, wd)
  zip_path = os.path.join(WORKDIR, "%s.zip" % wd)
  zipf = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED)
  zipdir(wd_path, zipf)
  zipf.close()
  ev_hash = str(hashlib.sha256(open(zip_path, 'rb').read()).hexdigest()).upper()
  ev_b64 = ""
  with open(zip_path, 'rb') as fd:
    ev_b64 = base64.b64encode(fd.read())
  ev = {
      "caseId": caseid,
      "hash": ev_hash,
      "filename": os.path.basename(zip_path),
      "origin": "TUB_stream",
      "content": ev_b64.decode('ascii')}
  res = requests.post(LOCARD_SERVER,
      verify=False,
      auth=(USER, PASSWORD),
      data=mk_ev_str(ev))
  print(ev['caseId'])
  print(ev['hash'])
  print(ev['filename'])
  #json={"caseId":str(caseid), "hash":str(ev_hash), "filname": zip_path, "content":str(ev_b64)})
  print(res)
  print(res.content)


def worker_train(caseid, invid, case_uuid, case_workdir, model_out_path):
  print("WORKING ON: %s, %s" % (model_out_path, case_workdir))
  datas_path = os.path.join(case_workdir, TDATADIR, DATASFN)
  datan_path = os.path.join(case_workdir, TDATADIR, DATANFN)
  train_csv = os.path.join(case_workdir, TRAINCSVFN)

  out_csv_fd = open(train_csv, "w")
  out_csv_fd.write("label;timestamp;len;sip;dip;sport;dport\n")
  print("COLLECTION STREAM PCAPS %s" % datas_path)
  for file_name in os.listdir(datas_path):
    print("PROCESS STREAM PCAP: %s" % file_name)
    TS.process_pcap(os.path.join(datas_path, file_name), out_csv_fd, 1)
  print("COLLECTION NORMAL PCAPS %s" % datas_path)
  for file_name in os.listdir(datan_path):
    print("PROCESS NORMAL PCAP: %s" % file_name)
    TS.process_pcap(os.path.join(datan_path, file_name), out_csv_fd, 0)

  model = TS.trainModel(train_csv)
  pickle.dump(model, open(model_out_path, 'wb'))

def worker_predict(caseid, invid, case_uuid, case_workdir, model_path):
  print("WORKING ON: %s, %s" % (model_path, case_workdir))
  csv_path = os.path.join(case_workdir, DATACSVFN)
  loaded_model = pickle.load(open(model_path, 'rb'))
  ret = TS.predictStreams(loaded_model, csv_path)
  with open(os.path.join(case_workdir, RESFN), "w") as fd:
    fd.write(json.dumps(ret, indent=2))
  return ret
  #send_evidence(caseid, invid, case_uuid, case_workdir)

@app.route('/train', methods=['POST'])
def train():
  print("Starting Training")
  content = request.json
  try:
    caseid = content['caseId']
    invid = content['invId']
    data = content['data']
    model_id = content['model_id']
  except:
    print("ERROR invalid json")
    return jsonify({"Error": "Invalid json"})

  res = {}
  case_uuid = str(uuid.uuid4())
  wd = "_".join([caseid, invid, case_uuid])
  res["workdir"] = wd
  case_workdir = os.path.join(WORKDIR, wd)
  print("CASE WORKDIR: %s" % case_workdir)
  os.mkdir(case_workdir)
  data_zip = os.path.join(case_workdir, "data.zip")

  # data archive must contain pcaps
  # format:
  # data
  # data/norm
  # data/stream
  data_decoded = None
  try:
    data_decoded = base64.b64decode(data)
  except:
    data_bytes = json.loads(data)
    data = ''.join(map(chr,data_bytes))
    data_decoded = base64.b64decode(data)
  if data_decoded is None:
    print("ERROR could not decode data")
    return jsonify({"Error": "could not decode data"})

  print("DATA ARCHIVE: %s" % data_zip)
  with open(data_zip, "wb") as fd:
    fd.write(data_decoded)
  with zipfile.ZipFile(data_zip, 'r') as zip_ref:
    zip_ref.extractall(case_workdir)

  model_out_path = os.path.join(MODELDIR, model_id + "_" + wd + ".mdl")

  p = multiprocessing.Process(target=worker_train, args=(caseid, invid, case_uuid, case_workdir, model_out_path))
  p.start()
  run_train[wd] = p
  res["model"] = model_out_path
  #RUNNING.append(p)
  return jsonify(res)

def process_pcap(file_name, label, out_fn):
  with open(out_fn, "w") as fd:
    fd.write("label;timestamp;len;sip;dip;sport;dport\n")
    for x in RawPcapReader(file_name):
        pkt_data = x

        ether_pkt = Ether(pkt_data)
        if IP not in ether_pkt or TCP not in ether_pkt:
           continue
        if 'type' not in ether_pkt.fields:
            continue

        if ether_pkt.type != 0x0800:
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            continue

        tcp_pkt = ether_pkt[TCP]
        if tcp_pkt.sport != 443 and tcp_pkt.dport != 443 and tcp_pkt.sport != 80 and tcp_pkt.dport != 80:
           continue
        #print("%d;%d;%d;%s;%s;%d;%d" % (label, ether_pkt.time, len(tcp_pkt), ip_pkt.src, ip_pkt.dst, tcp_pkt.sport, tcp_pkt.dport))
        fd.write("%d;%d;%d;%s;%s;%d;%d\n" % (label, ether_pkt.time, len(tcp_pkt), ip_pkt.src, ip_pkt.dst, tcp_pkt.sport, tcp_pkt.dport))


@app.route('/predict', methods=['POST'])
def predict():
  content = request.json
  print(json.dumps(content, indent=2))
  try:
    caseid = content['caseId']
    invid = content['invId']
    model_name = content['model']
    model_path = os.path.join(MODELDIR, model_name + ".mdl")
    data = content['data']
  except:
    print("ERROR invalid json")
    return jsonify({"Error": "Invalid json"})

  if not os.path.exists(model_path):
    print("ERROR invalid model")
    return jsonify({"Error": "Invalid model"})

  res = {}
  case_uuid = str(uuid.uuid4())
  wd = "_".join([caseid, invid, case_uuid])
  res["workdir"] = wd
  case_workdir = os.path.join(WORKDIR, wd)
  print("CASE WORKDIR: %s" % case_workdir)
  os.mkdir(case_workdir)
  data_csv_fn = os.path.join(case_workdir, DATACSVFN)
  data_pcap_fn = os.path.join(case_workdir, DATAPCPFN)
  data_dec = None
  try:
    data_dec = base64.b64decode(data)
  except:
    data_bytes = json.loads(data)
    data = ''.join(map(chr,data_bytes))
    data_dec = base64.b64decode(data)
  if data_dec is None:
    print("Failed to decode data")
    return jsonify({"Error": "Failed to decode data"})
  #data_dec = data_dec.replace(" ", "")
  #data_lab = []
  #for i, datal in enumerate(data_dec.splitlines()):
  #  if i == 0:
  #    data_lab.append("label;"+datal)
  #  else:
  #    data_lab.append("0;"+datal)
  print("DATA PCAP: %s" % data_pcap_fn)
  with open(data_pcap_fn, "wb") as fd:
    #fd.write("\n".join(data_lab))
    fd.write(data_dec)
  print("DATA CSV:  %s" % data_csv_fn)
  #with open(data_csv_fn, "w") as fd:
  #  fd.write("\n".join(data_lab))
  process_pcap(data_pcap_fn, 0, data_csv_fn)

  #p = multiprocessing.Process(target=worker_predict, args=(caseid, invid, case_uuid, case_workdir, model_path))
  #p.start()
  pred = worker_predict(caseid, invid, case_uuid, case_workdir, model_path)
  #run_predict[wd] = p
  #RUNNING.append(p)
  return jsonify(pred)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5003)
