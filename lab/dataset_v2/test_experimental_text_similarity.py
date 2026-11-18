import copy
import unittest
import numpy as np
from .experimental_text_similarity import DescriptionSimilarity,normalise_description,local_embedding_cosine


class TextSimilarityTests(unittest.TestCase):
    def fitted(self):
        return DescriptionSimilarity().fit_development(['SSH login failure','SSH authentication failure','File integrity changed'],
            [{'group_id':'synthetic-train','partition':'development'}]*3,allowed_training_groups={'synthetic-train'})

    def test_similarity_and_empty_unknown_text(self):
        model=self.fitted()
        self.assertAlmostEqual(model.pair_similarity('SSH login failure','SSH login failure'),1.)
        self.assertEqual(model.pair_similarity('','never_seen_token'),0.)

    def test_validation_test_and_heldout_groups_never_fit_vocabulary(self):
        for partition,group in [('validation','train'),('final-test','train'),('development','heldout')]:
            with self.subTest(partition=partition,group=group):
                with self.assertRaises(PermissionError):
                    DescriptionSimilarity().fit_development(['private secret'],[{'group_id':group,'partition':partition}],allowed_training_groups={'train'})

    def test_campaign_markers_uuids_and_metadata_removed(self):
        text='SSH agv2-abcdef123456 dev-example-20000101-001-r01 11111111-1111-4111-8111-111111111111'
        self.assertEqual(normalise_description(text),'ssh')
        self.assertEqual(normalise_description('SSH private-marker',markers=['private-marker']),'ssh')

    def test_private_fields_rejected_and_raw_alert_not_modified(self):
        with self.assertRaises(ValueError):normalise_description('activity_id=secret')
        alert={'rule':{'description':'SSH login'},'target':1,'activity_id':'private','full_log':'private receipt'}
        before=copy.deepcopy(alert)
        self.assertEqual(normalise_description(alert),'ssh login');self.assertEqual(alert,before)

    def test_transform_does_not_learn_new_words(self):
        model=self.fitted();before=dict(model.vectorizer.vocabulary_)
        model.pair_similarity('heldoutnovelword','ssh login')
        self.assertEqual(model.vectorizer.vocabulary_,before)

    def test_causality_and_existing_similarity_preserved(self):
        base={'causal_compatibility':.8,'entity_similarity':.5};before=dict(base)
        result=self.fitted().augment_pair(base,'ssh login','ssh failure')
        self.assertEqual(base,before)
        self.assertEqual(result['causal_compatibility'],.8);self.assertEqual(result['entity_similarity'],.5)

    def test_embedding_is_optional_local_injection_only(self):
        class Encoder:
            def encode(self,texts):return np.array([[1,0],[1,0]])
        self.assertEqual(local_embedding_cosine('a','b',local_encoder=Encoder()),1.)
        class Bad:
            def encode(self,texts):return np.array([[float('nan')],[1.]])
        with self.assertRaises(ValueError):local_embedding_cosine('a','b',local_encoder=Bad())


if __name__=='__main__':unittest.main()
