#! /usr/bin/env python3

import argparse
import logging
import OpenSSL
import traceback
import sys
import datetime
import pyasn1.codec.der.decoder
import pyasn1.codec.native.encoder
import pyasn1_modules.rfc2459
import logging
logger = logging.getLogger('certverify')

class CertVerify:
    def __init__(self):
        self.certificate_filepath = None
        self.certificate = None
        self.privatekey_filepath = None
        self.privatekey = None
        self.certificate_request_filepath = None
        self.certificate_request = None
        self.ssl_context = None
        self.results = []
        self.argparser = argparse.ArgumentParser()
        self.argparser.add_argument('-o', '--output', help='output style', choices=['check', 'renew', 'add-domain'], default='check')
        self.argparser.add_argument('--new-domains', dest='new_domains', nargs='+')
        self.argparser.add_argument('certificate_filepath')
        self.argparser.add_argument('privatekey_filepath')
        self.argparser.add_argument('certificate_request_filepath')

    def init_logger(self):
        h = logging.StreamHandler(sys.stderr)
        fmtr = logging.Formatter('[%(asctime)s] %(levelname)-8s %(filename)s:%(lineno)d %(funcName)s - %(message)s')
        h.setFormatter(fmtr)
        logger.addHandler(h)
        logger.setLevel(logging.DEBUG)

    def parse_args(self):
        args = self.argparser.parse_args()
        self.certificate_filepath = args.certificate_filepath
        self.certificate_request_filepath = args.certificate_request_filepath
        self.privatekey_filepath = args.privatekey_filepath
        self.output_style = args.output
        self.new_domains = args.new_domains

    def load_files(self):
        self.certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(self.certificate_filepath, 'r').read())
        self.certificate_request = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, open(self.certificate_request_filepath, 'r').read())
        self.privatekey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open(self.privatekey_filepath, 'r').read())
        self.ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)

    def check_certificate_match_privatekey(self):
        self.ssl_context.use_certificate(self.certificate)
        self.ssl_context.use_privatekey(self.privatekey)
        try:
            self.ssl_context.check_privatekey()
            self.results.append(('certificate match privatekey', 1, 'passed'))
        except OpenSSL.SSL.Error as e:
            self.results.append(('certificate match privatekey', 0, str(e)))

    def _pkey_match_request(self, pkey, check_item='pkey match request'):
        try:
            res = self.certificate_request.verify(pkey)
            if res:
                self.results.append((check_item, 1, 'passed'))
            else:
                self.results.append((check_item, 0, 'failed'))
        except OpenSSL.crypto.Error as e:
            self.results.append((check_item, 0, str(e)))

    def check_certificate_match_request(self):
        self._pkey_match_request(self.certificate.get_pubkey(), 'certificate match request')

    def check_privatekey_match_request(self):
        self._pkey_match_request(self.privatekey, 'privatekey match request')

    def sort_hostnames(self, hostnames):
        rows = [h.split('.') for h in hostnames]
        for r in rows:
            r.reverse()
        rows.sort()
        for r in rows:
            r.reverse()
        lines = ['.'.join(r) for r in rows]
        return lines

    def decode_subject_alt_names(self, buf):
        decoded_alt_names, rest = pyasn1.codec.der.decoder.decode(buf, asn1Spec=pyasn1_modules.rfc2459.SubjectAltName())
        alt_name_lines = pyasn1.codec.native.encoder.encode(decoded_alt_names)
        alt_names = [i['dNSName'].decode('utf-8') for i in alt_name_lines]
        return self.sort_hostnames(alt_names)

    def get_alt_names(self):
        ret = []
        for i in range(0, self.certificate.get_extension_count()):
            ext = self.certificate.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                alt_names = self.decode_subject_alt_names(ext.get_data())
                ret += alt_names
        return ret

    def get_noafter(self):
        return datetime.datetime.strptime(self.certificate.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')

    def get_nobefore(self):
        return datetime.datetime.strptime(self.certificate.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')

    def output_renew(self):
        subject = self.certificate.get_subject()
        print(f'Organization Name: {subject.organizationName}')
        print(f'Country Name: {subject.countryName}')
        print(f'State or Province Name: {subject.stateOrProvinceName}')
        print(f'Locality Name: {subject.localityName}')

        notafter = self.get_noafter()
        print(f'Not After: {notafter}')
        notbefore = self.get_nobefore()
        print(f'Not Before: {notbefore}')

        common_name = subject.commonName
        alt_names = self.get_alt_names()
        if self.output_style == 'add-domain':
            for h in self.new_domains:
                if h in alt_names:
                    raise ValueError(f'domain {h} is already in this certificate')
            alt_names += self.new_domains
        alt_names.remove(common_name)
        
        print(f'Common Name: {subject.commonName}')
        print(f'Alternative Names: {";".join(alt_names)}')
        if self.output_style == 'add-domain':
            print(f'New Names: {";".join(self.new_domains)}')

    def output_check(self):
        print('Summary:')
        print('Subject:')
        subject = self.certificate.get_subject()
        for k, v in subject.get_components():
            print(f'{k.decode("utf-8")}: {v.decode("utf-8")}')

        print('Issuer:')
        for k, v in self.certificate.get_issuer().get_components():
            print(f'{k.decode("utf-8")}: {v.decode("utf-8")}')

        print('Extensions:')
        alt_names = self.get_alt_names()
        max_width = 0
        for h in alt_names:
            if len(h) > max_width:
                max_width = len(h)
        for h in alt_names:
            print(f'{h:>{4+max_width}}')

        notafter = self.get_noafter()
        print(f'Not After: {notafter}')
        notbefore = self.get_nobefore()
        print(f'Not Before: {notbefore}')
        print('Check Results:')
        for r in self.results:
            print(f'{r[0]}: {r[1]}, {r[2]}')

    def output(self):
        if self.output_style == 'check':
            self.output_check()
        elif self.output_style in ['renew', 'add-domain']:
            self.output_renew()

    def main(self):
        try:
            self.init_logger()
            self.parse_args()
            self.load_files()
            self.check_certificate_match_privatekey()
            self.check_privatekey_match_request()
            self.check_certificate_match_request()
            self.output()
            return 0
        except Exception as e:
            logger.error(f'Exception {e} occured', exc_info=sys.exc_info())
            return 1

if __name__ == '__main__':
    sys.exit(CertVerify().main())
        
        

        




        
