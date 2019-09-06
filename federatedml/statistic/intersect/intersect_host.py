#
#  Copyright 2019 The FATE Authors. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import hashlib

from arch.api import eggroll
from arch.api.federation import remote, get
from arch.api.utils import log_utils
from federatedml.secureprotol import gmpy_math
from federatedml.secureprotol.encrypt import RsaEncrypt
from federatedml.statistic.intersect import RawIntersect
from federatedml.statistic.intersect import RsaIntersect
from federatedml.util import cache_utils
from federatedml.util import consts
from federatedml.util.check import check_eq
from federatedml.util.transfer_variable.rsa_intersect_transfer_variable import RsaIntersectTransferVariable

LOGGER = log_utils.getLogger()


class RsaIntersectionHost(RsaIntersect):
    def __init__(self, intersect_params):
        super().__init__(intersect_params)

        self.synchronize_intersect_ids = intersect_params.synchronize_intersect_ids
        self.transfer_variable = RsaIntersectTransferVariable()

        self.e = None
        self.d = None
        self.n = None

        # parameter for intersection cache
        self.intersect_cache_param = intersect_params.intersect_cache_param
        self.current_version = None
        self.is_version_match = False
        self.has_cache_version = True

    @staticmethod
    def hash(value):
        return hashlib.sha256(bytes(str(value), encoding='utf-8')).hexdigest()

    def cal_host_ids_process_pair(self, data_instances: eggroll.table) -> eggroll.table:
        return data_instances.map(
            lambda k, v: (
                RsaIntersectionHost.hash(gmpy_math.powmod(int(RsaIntersectionHost.hash(k), 16), self.d, self.n)), k)
        )

    def generate_rsa_key(self, rsa_bit=1024):
        encrypt_operator = RsaEncrypt()
        encrypt_operator.generate_key(rsa_bit)
        return encrypt_operator.get_key_pair()

    def run(self, data_instances):
        LOGGER.info("Start rsa intersection")

        if self.use_cache:
            LOGGER.info("Using intersection cache scheme, start to getting rsa key from cache.")
            rsa_key = cache_utils.get_rsa_of_current_version(host_party_id=self.host_party_id,
                                                             id_type=self.intersect_cache_param.id_type,
                                                             encrypt_type=self.intersect_cache_param.encrypt_type,
                                                             tag='Za')
            if rsa_key is not None:
                self.e = rsa_key.get('rsa_e')
                self.d = rsa_key.get('rsa_d')
                self.n = rsa_key.get('rsa_n')
            else:
                self.has_cache_version = False
                LOGGER.info("Use cache but can not find any version in cache, set has_cache_version to false")
                LOGGER.info("Stay to generate rsa key")

                self.e, self.d, self.n = self.generate_rsa_key()
        else:
            LOGGER.info("Generate rsa keys.")
            self.e, self.d, self.n = self.generate_rsa_key()

        public_key = {"e": self.e, "n": self.n}
        remote(public_key,
               name=self.transfer_variable.rsa_pubkey.name,
               tag=self.transfer_variable.generate_transferid(self.transfer_variable.rsa_pubkey),
               role=consts.GUEST,
               idx=0)
        LOGGER.info("Remote public key to Guest.")

        version = None
        namespace = None

        # (host_id_process, 1)
        if self.use_cache:
            if self.has_cache_version:
                self.current_version = cache_utils.host_get_current_verison(host_party_id=self.host_party_id,
                                                                            id_type=self.intersect_cache_param.id_type,
                                                                            encrypt_type=self.intersect_cache_param.encrypt_type,
                                                                            tag='Za')

                guest_current_version = get(name=self.transfer_variable.cache_version_info.name,
                                            tag=self.transfer_variable.generate_transferid(
                                                self.transfer_variable.cache_version_info),
                                            idx=0)

                if check_eq(guest_current_version.get('table_name'), self.current_version.get('table_name')) and \
                        check_eq(guest_current_version.get('namespace'), self.current_version.get('namespace')) and \
                        self.current_version is not None:
                    self.is_version_match = True
                else:
                    self.is_version_match = False

                if not self.is_version_match or self.synchronize_intersect_ids:
                    # if self.synchronize_intersect_ids is true, host will get the encrypted intersect id from guest,
                    # which need the Za to decrypt them
                    LOGGER.info("read Za from cache")
                    host_ids_process_pair = eggroll.table(name=self.current_version.get('table_name'),
                                                          namespace=self.current_version.get('namespace'),
                                                          create_if_missing=True,
                                                          error_if_exist=False)
                    if check_eq(host_ids_process_pair.count(), 0):
                        host_ids_process_pair = self.cal_host_ids_process_pair(data_instances)
            else:
                self.is_version_match = False
                host_ids_process_pair = self.cal_host_ids_process_pair(data_instances)
                store_cache_ret = cache_utils.store_cache(dtable=host_ids_process_pair,
                                                          guest_party_id=self.guest_party_id,
                                                          host_party_id=self.host_party_id,
                                                          version=None,
                                                          id_type=self.intersect_cache_param.id_type,
                                                          encrypt_type=self.intersect_cache_param.encrypt_type,
                                                          tag='Za')
                version = store_cache_ret.get('table_name')
                namespace = store_cache_ret.get('namespace')
                cache_utils.store_rsa(host_party_id=self.host_party_id,
                                      id_type=self.intersect_cache_param.id_type,
                                      encrypt_type=self.intersect_cache_param.encrypt_type,
                                      tag='Za',
                                      namespace=namespace,
                                      version=version,
                                      rsa={'rsa_e': self.e, 'rsa_d': self.d, 'rsa_n': self.n})

            LOGGER.info("version_match:{}".format(self.is_version_match))

            version_match_info = {'version_match': self.is_version_match,
                                  'version': version,
                                  'namespace': namespace}
            remote(version_match_info,
                   name=self.transfer_variable.cache_version_match_info.name,
                   tag=self.transfer_variable.generate_transferid(self.transfer_variable.cache_version_match_info),
                   role=consts.GUEST,
                   idx=0)
            LOGGER.info("remote version match info to guest")
        else:
            LOGGER.info("calculate Za using raw id")
            host_ids_process_pair = self.cal_host_ids_process_pair(data_instances)

        if self.use_cache and not self.is_version_match:
            host_ids_process = host_ids_process_pair.mapValues(lambda v: 1)
            remote(host_ids_process,
                   name=self.transfer_variable.intersect_host_ids_process.name,
                   tag=self.transfer_variable.generate_transferid(self.transfer_variable.intersect_host_ids_process),
                   role=consts.GUEST,
                   idx=0)

            LOGGER.info("Remote host_ids_process to Guest.")

        # Recv guest ids
        guest_ids = get(name=self.transfer_variable.intersect_guest_ids.name,
                        tag=self.transfer_variable.generate_transferid(self.transfer_variable.intersect_guest_ids),
                        idx=0)
        LOGGER.info("Get guest_ids from guest")

        # Process guest ids and return to guest
        guest_ids_process = guest_ids.map(lambda k, v: (k, gmpy_math.powmod(int(k), self.d, self.n)))
        remote(guest_ids_process,
               name=self.transfer_variable.intersect_guest_ids_process.name,
               tag=self.transfer_variable.generate_transferid(self.transfer_variable.intersect_guest_ids_process),
               role=consts.GUEST,
               idx=0)
        LOGGER.info("Remote guest_ids_process to Guest.")

        # recv intersect ids
        intersect_ids = None
        if self.synchronize_intersect_ids:
            encrypt_intersect_ids = get(name=self.transfer_variable.intersect_ids.name,
                                        tag=self.transfer_variable.generate_transferid(
                                            self.transfer_variable.intersect_ids),
                                        idx=0)

            intersect_ids_pair = encrypt_intersect_ids.join(host_ids_process_pair, lambda e, h: h)
            intersect_ids = intersect_ids_pair.map(lambda k, v: (v, "intersect_id"))
            LOGGER.info("Get intersect ids from Guest")

            if not self.only_output_key:
                intersect_ids = self._get_value_from_data(intersect_ids, data_instances)

        return intersect_ids


class RawIntersectionHost(RawIntersect):
    def __init__(self, intersect_params):
        super().__init__(intersect_params)
        self.join_role = intersect_params.join_role
        self.role = consts.HOST

    def run(self, data_instances):
        LOGGER.info("Start raw intersection")

        if self.join_role == consts.GUEST:
            intersect_ids = self.intersect_send_id(data_instances)
        elif self.join_role == consts.HOST:
            intersect_ids = self.intersect_join_id(data_instances)
        else:
            raise ValueError("Unknown intersect join role, please check the configure of host")

        return intersect_ids
