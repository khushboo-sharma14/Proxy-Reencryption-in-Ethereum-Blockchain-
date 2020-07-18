import uuid
import random
from typing import List

from umbral import pre, fragments
import requests 
import json


class MockNetwork(object):

    def __init__(self):
        self.db = {}

    def grant(self, kfrags: List[fragments.KFrag]) -> str:
        """
        Creates a mock Policy on the NuCypher network.

        :param kfrags: A list of Umbral KFrags.

        :return: NuCypher Policy ID (str)
        """
        policy_id = str(uuid.uuid4())

        self.db[policy_id] = kfrags
        return policy_id

    def reencrypt(self, policy_id: str, capsule: pre.Capsule, M: int) -> List[fragments.CapsuleFrag]:
        """
        Re-encrypts the given capsule 'M' number of times and returns a list
        of CapsuleFrags (CFrags) to be attached to the original Capsule.

        :param policy_id: Policy ID to access re-encryption.
        :param capsule: The Umbral capsule to re-encrypt.
        :param M: The number of times to re-encrypt the capsule for the minimum
            number of CFrags needed.

        :return: List of CFrags (CapsuleFrags).
        """
        try:
            kfrags = self.db[policy_id]
        except KeyError:
            raise ValueError("No Policy found for {}".format(policy_id))

        if M > len(kfrags):
            raise ValueError("Not enough KFrags to re-encrypt {} times!".format(M))
        
        cfrags = []

        # TODO: using web3py check if is dead?  
        try:
            data = requests.get("http://172.16.21.223:3000/api/platform/isAlive/"+str(policy_id))
            res = json.loads(data.text)
            if bool(res["result"]) == True:
                m_kfrags = random.sample(kfrags, M)
                for kfrag in m_kfrags:
                    cfrags.append(pre.reencrypt(kfrag, capsule))
                return cfrags
        except:
            return cfrags
            
    def revoke(self, policy_id: str):
        """
        Revokes the Policy on the mock NuCypher network by deleting the policy
        and the associated kfrags.
        :param policy_id: The policy_id to revoke.
        """
        del(self.db[policy_id])
