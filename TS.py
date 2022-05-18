import argparse
import pickle
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error
from sklearn.ensemble import RandomForestRegressor
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import argparse
import os
import sys
import numpy as np



class TS:
    def makeXY(df, minlen, maxlen):
        train_y = []
        train_x = []
        labels = []
        nfeat = maxlen
        for x, g in df.groupby(['sip', 'dip', 'sport', 'dport']):
            if len(g['len']) < minlen:
                continue
            train_y.append(g['label'].iloc[0])
            total_tx = g['len'].sum()
            total_len = len(g['len'].index)
            if total_len < nfeat:
                data = g['len'].to_numpy()
                data = np.pad(data, (0, nfeat-total_len), 'constant')
            else:
                data = g['len'][0:nfeat].to_numpy()

            data = np.insert(data, 0, total_tx)
            data = np.insert(data, 0, total_len)
            train_x.append(data)
            labels.append("_".join(map(lambda t: str(t), x)))
        return np.asarray(train_x), np.asarray(train_y), labels

    def trainModel(fn, minlen=1000, maxlen=50000, n_estimators=16):
        #sys.stderr.write("Train model on %s\n" % fn)
        df = pd.read_csv(fn, sep=";")
        df['sz'] = df.groupby(['sip', 'dip', 'sport', 'dport'])['len'].transform("size")
        train_x, train_y, _ = TS.makeXY(df, minlen, maxlen)
        model = RandomForestRegressor(n_estimators=n_estimators)
        model.fit(np.asarray(train_x), np.asarray(train_y))
        return model

    def predictStreams(model, fn, minlen=1000, maxlen=50000):
        #sys.stderr.write("Predict streams on %s\n" % fn)
        ret = {}
        df = pd.read_csv(fn, sep=";")
        train_x, train_y, labels = TS.makeXY(df, minlen, maxlen)
        yhat = model.predict(train_x)
        for l, p in zip(labels, yhat):
            print("%64s %f" % (l, p))
            ret[l] = p
        return ret

    def process_pcap(in_pcap_fn, out_csv_fd, label):
        #sys.stderr.write("Processing %s\n" % in_pcap_fn)
        for pkt_data in RawPcapReader(in_pcap_fn):
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
            out_csv_fd.write("%d;%d;%d;%s;%s;%d;%d\n" % (label, ether_pkt.time, len(tcp_pkt), ip_pkt.src, ip_pkt.dst, tcp_pkt.sport, tcp_pkt.dport))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcaps', metavar='<streaming pcap file name>',
                        help='streaming pcap directory to parse', required=True)
    parser.add_argument('--pcapn', metavar='<non streaming pcap file name>',
                        help='non streaming pcap directory to parse', required=True)
    parser.add_argument('--csv_out', metavar='<output csv file name>',
                        help='output csv file', required=True)
    parser.add_argument('--mod_out', metavar='<output model file name>',
                        help='output model file', required=True)
    args = parser.parse_args()

    csv_file = args.csv_out
    #out_csv_fd = open(csv_file, "w")
    #out_csv_fd.write("label;timestamp;len;sip;dip;sport;dport\n")
    #for file_name in os.listdir(args.pcaps):
    #  process_pcap(os.path.join(args.pcaps, file_name), out_csv_fd, 1)
    #for file_name in os.listdir(args.pcapn):
    #  process_pcap(os.path.join(args.pcapn, file_name), out_csv_fd, 0)
    #out_csv_fd.close()
    model = TS.trainModel(csv_file)
    pickle.dump(model, open(args.mod_out, 'wb'))
    TS.predictStreams(model, csv_file)
