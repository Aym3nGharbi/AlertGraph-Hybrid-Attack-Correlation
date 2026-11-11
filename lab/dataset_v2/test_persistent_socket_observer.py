from __future__ import annotations

import time
import unittest
from collections import namedtuple

from lab.dataset_v2.persistent_socket_observer import PersistentSocketObserver


Address=namedtuple("Address","ip port");Connection=namedtuple("Connection","laddr raddr status pid")


class PersistentSocketObserverTests(unittest.TestCase):
    def test_ready_precedes_observation_and_pid_filter_is_exact(self):
        calls=[[],[Connection(Address("192.168.122.1",50001),Address("192.168.122.130",22),"ESTABLISHED",101),
                   Connection(Address("192.168.122.1",50002),Address("192.168.122.130",22),"ESTABLISHED",202)]]
        def provider():
            return calls.pop(0) if calls else []
        observer=PersistentSocketObserver("192.168.122.130",22,poll_interval_seconds=0.001,provider=provider)
        observer.start();self.assertTrue(observer.ready);time.sleep(0.02);observer.stop()
        self.assertEqual({x["source_port"] for x in observer.observations(pid=101)},{50001})
        self.assertEqual({x["source_port"] for x in observer.observations(pid=202)},{50002})

    def test_unrelated_destination_is_not_recorded(self):
        connection=Connection(Address("192.168.122.1",50001),Address("203.0.113.2",22),"ESTABLISHED",101)
        observer=PersistentSocketObserver("192.168.122.130",22,poll_interval_seconds=0.001,provider=lambda:[connection])
        observer.start();time.sleep(0.01);observer.stop();self.assertEqual(observer.observations(),[])

    def test_observer_can_restart(self):
        observer=PersistentSocketObserver("192.168.122.130",22,poll_interval_seconds=0.001,provider=lambda:[])
        observer.start();observer.stop();observer.start();observer.stop();self.assertGreaterEqual(observer.health()["scans"],2)


if __name__=="__main__":unittest.main()
