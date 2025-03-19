import numpy as np
import panda as pd
import random

possible_values = {'duration': (np.int64(0), np.int64(57715)),
 'protocol_type': ['udp', 'tcp', 'icmp'],
 'service': ['private',
  'domain_u',
  'http',
  'smtp',
  'ftp_data',
  'ftp',
  'eco_i',
  'other',
  'auth',
  'ecr_i',
  'IRC',
  'X11',
  'finger',
  'time',
  'domain',
  'telnet',
  'pop_3',
  'ldap',
  'login',
  'name',
  'ntp_u',
  'http_443',
  'sunrpc',
  'printer',
  'systat',
  'tim_i',
  'netstat',
  'remote_job',
  'link',
  'urp_i',
  'sql_net',
  'bgp',
  'pop_2',
  'tftp_u',
  'uucp',
  'imap4',
  'pm_dump',
  'nnsp',
  'courier',
  'daytime',
  'iso_tsap',
  'echo',
  'discard',
  'ssh',
  'whois',
  'mtp',
  'gopher',
  'rje',
  'ctf',
  'supdup',
  'hostnames',
  'csnet_ns',
  'uucp_path',
  'nntp',
  'netbios_ns',
  'netbios_dgm',
  'netbios_ssn',
  'vmnet',
  'Z39_50',
  'exec',
  'shell',
  'efs',
  'klogin',
  'kshell',
  'icmp'],
 'flag': ['SF',
  'RSTR',
  'S1',
  'REJ',
  'S3',
  'RSTO',
  'S0',
  'S2',
  'RSTOS0',
  'SH',
  'OTH'],
 'src_bytes': (np.int64(0), np.int64(62825648)),
 'dst_bytes': (np.int64(0), np.int64(5203179)),
 'land': [0, 1],
 'wrong_fragment': [0, 1, 3],
 'urgent': [0, 2, 1, 3],
 'hot': (np.int64(0), np.int64(101)),
 'num_failed_logins': [0, 1, 4, 3, 2],
 'logged_in': [0, 1],
 'num_compromised': (np.int64(0), np.int64(796)),
 'root_shell': [0, 1],
 'su_attempted': [0, 1, 2],
 'num_root': (np.int64(0), np.int64(878)),
 'num_file_creations': [0, 3, 1, 5, 2, 4, 30, 12, 6, 100, 7, 13],
 'num_shells': [0, 2, 1, 5],
 'num_access_files': [0, 1, 4, 2, 3],
 'num_outbound_cmds': [0],
 'is_host_login': [0, 1],
 'is_guest_login': [0, 1],
 'count': (np.int64(0), np.int64(511)),
 'srv_count': (np.int64(0), np.int64(511)),
 'serror_rate': (np.float64(0.0), np.float64(1.0)),
 'srv_serror_rate': (np.float64(0.0), np.float64(1.0)),
 'rerror_rate': (np.float64(0.0), np.float64(1.0)),
 'srv_rerror_rate': (np.float64(0.0), np.float64(1.0)),
 'same_srv_rate': (np.float64(0.0), np.float64(1.0)),
 'diff_srv_rate': (np.float64(0.0), np.float64(1.0)),
 'srv_diff_host_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_count': (np.int64(0), np.int64(255)),
 'dst_host_srv_count': (np.int64(0), np.int64(255)),
 'dst_host_same_srv_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_diff_srv_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_same_src_port_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_srv_diff_host_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_serror_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_srv_serror_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_rerror_rate': (np.float64(0.0), np.float64(1.0)),
 'dst_host_srv_rerror_rate': (np.float64(0.0), np.float64(1.0)),
 'label': ['normal.',
  'snmpgetattack.',
  'named.',
  'xlock.',
  'smurf.',
  'ipsweep.',
  'multihop.',
  'xsnoop.',
  'sendmail.',
  'guess_passwd.',
  'saint.',
  'buffer_overflow.',
  'portsweep.',
  'pod.',
  'apache2.',
  'phf.',
  'udpstorm.',
  'warezmaster.',
  'perl.',
  'satan.',
  'xterm.',
  'mscan.',
  'processtable.',
  'ps.',
  'nmap.',
  'rootkit.',
  'neptune.',
  'loadmodule.',
  'imap.',
  'back.',
  'httptunnel.',
  'worm.',
  'mailbomb.',
  'ftp_write.',
  'teardrop.',
  'land.',
  'sqlattack.',
  'snmpguess.']}

categorical_features = ['protocol_type',
 'service',
 'flag',
 'land',
 'wrong_fragment',
 'urgent',
 'num_failed_logins',
 'logged_in',
 'root_shell',
 'su_attempted',
 'num_file_creations',
 'num_shells',
 'num_access_files',
 'num_outbound_cmds',
 'is_host_login',
 'is_guest_login',
 'label']

continuous_features = ['duration',
 'src_bytes',
 'dst_bytes',
 'hot',
 'num_compromised',
 'num_root',
 'count',
 'srv_count',
 'serror_rate',
 'srv_serror_rate',
 'rerror_rate',
 'srv_rerror_rate',
 'same_srv_rate',
 'diff_srv_rate',
 'srv_diff_host_rate',
 'dst_host_count',
 'dst_host_srv_count',
 'dst_host_same_srv_rate',
 'dst_host_diff_srv_rate',
 'dst_host_same_src_port_rate',
 'dst_host_srv_diff_host_rate',
 'dst_host_serror_rate',
 'dst_host_srv_serror_rate',
 'dst_host_rerror_rate',
 'dst_host_srv_rerror_rate']

def generate_continuous_value(value_range):
    """Génère une valeur continue aléatoire entre min et max."""
    min_val, max_val = value_range
    return random.uniform(min_val, max_val)  # Flottant aléatoire

def generate_fake_row(possible_values, continuous_features):
    """Génère une ligne factice en respectant les types de données."""
    fake_row = {}
    for col, values in possible_values.items():
        if col in continuous_features:
            fake_row[col] = generate_continuous_value(values)  # Génération réaliste entre min et max
        else:
            fake_row[col] = np.random.choice(values)  # Valeurs catégoriques aléatoires
    return fake_row

def generate_fake_data(possible_values, continuous_features, n=10):
    """Génère plusieurs lignes factices."""
    return pd.DataFrame([generate_fake_row(possible_values, continuous_features) for _ in range(n)])

def generate():
    return generate_fake_data(possible_values, continuous_features, n=10)
