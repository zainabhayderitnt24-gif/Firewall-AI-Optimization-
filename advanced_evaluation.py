"""v1.2: measured scalability and held-out synthetic anomaly experiments."""
from time import perf_counter
from statistics import median
from ipaddress import IPv4Address
from pathlib import Path
import platform
import random
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from analysis import COLUMNS, parse_rules, analyze, optimize, filter_packet
from ai_model import rule_features, detect_anomalies
from evaluation import random_packet

SIZES = (100, 500, 1000, 2000, 5000)
SEEDS = (42, 73, 109)
METHODS = ('Isolation Forest', 'Local Outlier Factor', 'One-Class SVM')

def scaling_rules(n):
    """Exactly n rules, using disjoint network blocks and repeatable patterns."""
    if not 1 <= n <= 5000:
        raise ValueError('Supported sizes: 1–5000')
    rows = []
    for g in range((n+11)//12):
        def addr(base, offset=0):
            return str(IPv4Address(int(IPv4Address(base)) + g*256 + offset))
        s = lambda offset=0: addr('10.0.0.0',offset)
        dns = lambda offset=0: addr('10.64.0.0',offset)
        ssh = lambda offset=0: addr('10.128.0.0',offset)
        d = lambda offset=0: addr('172.16.0.0',offset)
        block = [
            (s()+'/24',d()+'/24','any','443','tcp','allow'),
            (s()+'/24',d()+'/24','any','443','tcp','allow'),
            (s(16)+'/28',d(10),'any','443','tcp','allow'),
            (s(32)+'/28',d(11),'any','443','tcp','deny'),
            (dns()+'/24',d()+'/24','any','53','udp','allow'),
            (dns()+'/24',d()+'/24','any','53','udp','allow'),
            (dns(48)+'/28',d(8),'any','53','udp','deny'),
            (ssh()+'/27',d(5),'any','22','tcp','deny'),
            (ssh(5),d(5),'any','22','tcp','allow'),
            (addr('10.192.0.0')+'/27',addr('172.24.0.0')+'/27','any','8080','tcp','allow'),
            ('any',d()+'/24','any','80','tcp','deny'),
            (addr('10.224.0.0')+'/24',d(50),'any','8443','tcp','allow'),
        ]
        for rule in block:
            i = len(rows)+1
            if i > n: break
            rows.append((f'S{i:05d}',i,*rule))
    return pd.DataFrame(rows,columns=COLUMNS)


def scalability(repetitions=3, packet_samples=300, sizes=SIZES):
    """Actual pipeline times, measured without dataset generation or plotting."""
    rows, trials = [], []
    for n in sizes:
        frame = scaling_rules(n)
        for rep in range(1,repetitions+1):
            t0 = perf_counter(); rules = parse_rules(frame); t1 = perf_counter()
            report = analyze(rules); t2 = perf_counter()
            detect_anomalies(rules, contamination=.15); t3 = perf_counter()
            reduced = optimize(frame,report); optimized = parse_rules(reduced); t4 = perf_counter()
            trials.append(dict(rules=n, repeat=rep, parse_ms=(t1-t0)*1000,
                 rule_analysis_ms=(t2-t1)*1000, isolation_forest_ms=(t3-t2)*1000,
                 optimization_validation_ms=(t4-t3)*1000, total_ms=(t4-t0)*1000))
        matching = allows = 0
        rng = random.Random(2026)
        for _ in range(packet_samples):
            packet = random_packet(rng,rules)
            before = filter_packet(rules,*packet); after = filter_packet(optimized,*packet)
            matching += before == after; allows += before == 'allow'
        runs = trials[-repetitions:]
        row = dict(rules=n, removed_rules=n-len(reduced), optimized_rules=len(reduced),
                   reduction_pct=100*(n-len(reduced))/n, repetitions=repetitions,
                   packets_checked=packet_samples, matching_decisions=matching,
                   allow_decisions=allows, deny_decisions=packet_samples-allows)
        for key in ('parse_ms','rule_analysis_ms','isolation_forest_ms','optimization_validation_ms','total_ms'):
            row['median_'+key]=median(r[key] for r in runs)
        rows.append(row)
    return pd.DataFrame(rows), pd.DataFrame(trials)


def anomaly_data(seed, normal_count, anomalous_count=0):
    """Controlled synthetic statistical outliers, not real-world threat labels."""
    rng = random.Random(seed)
    records = []
    def ordinary():
        subnet = rng.randrange(1,64); dest = rng.randrange(1,40)
        src = f'10.10.{subnet}.0/24' if rng.random()<.75 else f'10.10.{subnet}.{rng.randrange(1,255)}'
        dst = f'172.20.{dest}.{rng.randrange(1,255)}' if rng.random()<.75 else f'172.20.{dest}.0/24'
        protocol, port = rng.choice([('tcp','443'),('tcp','80'),('tcp','22'),('udp','53'),('tcp','8080'),('udp','123')])
        sp = rng.choices(['any','1024-65535','49152-65535'],[.6,.25,.15])[0]
        return dict(src_ip=src,dst_ip=dst,src_port=sp,dst_port=port,protocol=protocol,action=rng.choices(['allow','deny'],[.8,.2])[0])
    for i in range(normal_count+anomalous_count):
        r = ordinary(); typ = 'normal'
        if i >= normal_count:
            typ = ['broad_source','broad_destination','unusual_service','wide_destination_ports','unusual_network','rare_protocol_scope'][(i-normal_count)%6]
            if typ=='broad_source': r['src_ip']=rng.choice(['any','10.0.0.0/8','10.10.0.0/16'])
            elif typ=='broad_destination': r['dst_ip']=rng.choice(['any','172.16.0.0/12','172.20.0.0/16'])
            elif typ=='unusual_service': r['dst_port']=str(rng.choice([4444,3389,5900,8443,10000,22000]))
            elif typ=='wide_destination_ports': r['dst_port']=rng.choice(['any','20-1024','400-9000'])
            elif typ=='unusual_network': r['src_ip']=f'192.0.2.{rng.randrange(1,255)}'; r['dst_ip']=f'198.51.100.{rng.randrange(1,255)}'
            else: r['protocol']='any'
        records.append((r,typ))
    rng.shuffle(records)
    rows=[]; labels=[]
    for i,(r,typ) in enumerate(records,1):
        rid=f'A{i:05d}'; rows.append(dict(rule_id=rid,priority=i,**r)); labels.append(dict(rule_id=rid,anomaly_type=typ,is_anomaly=int(typ!='normal')))
    return pd.DataFrame(rows,columns=COLUMNS),pd.DataFrame(labels)


def features(frame):
    # Priority and rule ID are not used: they are arbitrary identifiers/order in this benchmark.
    return rule_features(parse_rules(frame)).drop(columns=['priority']).to_numpy(dtype=float)


def algorithm_comparison(seeds=SEEDS, normal_training=600, normal_calibration=300, normal_test=900, anomalies_test=100):
    """Same data and train-only scaling; thresholds calibrated at nominal 5% FPR."""
    trials=[]; predictions=[]
    for seed in seeds:
        train,_=anomaly_data(seed*10+1,normal_training)
        cal,_=anomaly_data(seed*10+2,normal_calibration)
        test,labels=anomaly_data(seed*10+3,normal_test,anomalies_test)
        xtr,xcal,xte=map(features,(train,cal,test))
        scaler=StandardScaler().fit(xtr); xtr=scaler.transform(xtr); xcal=scaler.transform(xcal); xte=scaler.transform(xte)
        y=labels.is_anomaly.to_numpy()
        models=[IsolationForest(n_estimators=100,contamination='auto',random_state=seed,n_jobs=1),
                LocalOutlierFactor(n_neighbors=20,novelty=True,n_jobs=1),
                OneClassSVM(kernel='rbf',gamma='scale',nu=.05)]
        for method,model in zip(METHODS,models):
            t0=perf_counter(); model.fit(xtr); t1=perf_counter()
            cal_scores=-model.decision_function(xcal); threshold=float(np.quantile(cal_scores,.95)); t2=perf_counter()
            scores=-model.decision_function(xte); pred=(scores>threshold).astype(int); t3=perf_counter()
            tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
            trials.append(dict(seed=seed,algorithm=method,train_normal=len(xtr),calibration_normal=len(xcal),test_rules=len(xte),test_anomalies=int(y.sum()),
                tn=int(tn),fp=int(fp),fn=int(fn),tp=int(tp),accuracy=accuracy_score(y,pred),precision=precision_score(y,pred,zero_division=0),recall=recall_score(y,pred,zero_division=0),f1=f1_score(y,pred,zero_division=0),roc_auc=roc_auc_score(y,scores),false_positive_rate=fp/(fp+tn),calibration_fpr=float(np.mean(cal_scores>threshold)),threshold=threshold,fit_ms=(t1-t0)*1000,calibration_ms=(t2-t1)*1000,test_scoring_ms=(t3-t2)*1000,total_model_ms=(t3-t0)*1000))
            detail=labels.copy(); detail['seed']=seed; detail['algorithm']=method; detail['predicted_anomaly']=pred; detail['anomaly_score']=scores; detail['threshold']=threshold
            predictions.append(detail)
    raw=pd.DataFrame(trials); summary=[]
    for method in METHODS:
        sub=raw[raw.algorithm==method]; r={'algorithm':method,'trials':len(sub)}
        for col in ('accuracy','precision','recall','f1','roc_auc','false_positive_rate','calibration_fpr'):
            r['mean_'+col]=sub[col].mean(); r['sd_'+col]=sub[col].std(ddof=0)
        for col in ('fit_ms','calibration_ms','test_scoring_ms','total_model_ms'):
            r['median_'+col]=sub[col].median()
        for col in ('tn','fp','fn','tp'): r['total_'+col]=int(sub[col].sum())
        summary.append(r)
    return pd.DataFrame(summary),raw,pd.concat(predictions,ignore_index=True)


def runtime_info():
    import sklearn
    import matplotlib
    return f'Python {platform.python_version()} | scikit-learn {sklearn.__version__} | NumPy {np.__version__} | pandas {pd.__version__} | Matplotlib {matplotlib.__version__} | {platform.system()} {platform.machine()}'


def scalability_figure(table):
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(8.5,4.6))
    ax.plot(table.rules,table.median_total_ms,marker='o',linewidth=2,label='Full analysis pipeline')
    ax.plot(table.rules,table.median_rule_analysis_ms,marker='s',linestyle='--',label='Deterministic rule analysis')
    ax.plot(table.rules,table.median_isolation_forest_ms,marker='^',linestyle=':',label='Isolation Forest')
    ax.set(xlabel='Number of firewall rules',ylabel='Median execution time (ms)',title='Firewall optimizer scalability (measured)')
    ax.set_xticks(table.rules); ax.grid(alpha=.25); ax.legend(); fig.tight_layout(); return fig


def comparison_figure(table):
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(8.5,4.6)); x=np.arange(len(table)); w=.18
    for i,k in enumerate(['accuracy','precision','recall','f1']):
        ax.bar(x+(i-1.5)*w,table['mean_'+k],w,label=k.title())
    ax.set_xticks(x,table.algorithm); ax.set_ylim(0,1.10); ax.set_ylabel('Mean score (3 trials)'); ax.set_title('Held-out synthetic anomaly detection'); ax.legend(ncol=2); ax.grid(axis='y',alpha=.25); fig.tight_layout(); return fig


def export_local(output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    output=Path(output); output.mkdir(parents=True,exist_ok=True)
    scale, timings=scalability(); comp, trials, preds=algorithm_comparison()
    for name,data in [('scalability_100_to_5000',scale),('scalability_raw_timings',timings),('algorithm_comparison',comp),('algorithm_trials',trials),('algorithm_predictions',preds)]:
        data.to_csv(output/(name+'.csv'),index=False,float_format='%.6f')
    for name,fig in [('scalability_curve',scalability_figure(scale)),('algorithm_comparison_chart',comparison_figure(comp))]:
        fig.savefig(output/(name+'.png'),dpi=170); plt.close(fig)
    (output/'runtime_environment.txt').write_text(runtime_info()+'\nLocal software measurements, not Streamlit cloud timings.\n',encoding='utf-8')
    print(scale.to_string(index=False)); print(comp[['algorithm','mean_accuracy','mean_precision','mean_recall','mean_f1','mean_roc_auc','median_total_model_ms']].to_string(index=False))
    return scale,comp

if __name__=='__main__':
    export_local(Path(__file__).resolve().parent/'results'/'v1.2_local')
