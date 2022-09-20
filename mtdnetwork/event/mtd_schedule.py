import logging
from mtdnetwork.mtd.completetopologyshuffle import CompleteTopologyShuffle
from mtdnetwork.mtd.ipshuffle import IPShuffle
from mtdnetwork.mtd.hosttopologyshuffle import HostTopologyShuffle
from mtdnetwork.mtd.portshuffle import PortShuffle
from mtdnetwork.mtd.osdiversity import OSDiversity
from mtdnetwork.mtd.servicediversity import ServiceDiversity
from mtdnetwork.mtd.usershuffle import UserShuffle

# parameters for capacity of application layer and network layer
MTD_HYBRID = [CompleteTopologyShuffle, IPShuffle, HostTopologyShuffle,
              PortShuffle, OSDiversity, ServiceDiversity, UserShuffle]
MTD_SHUFFLE = [CompleteTopologyShuffle, IPShuffle, HostTopologyShuffle, PortShuffle]
MTD_DIVERSITY = [OSDiversity, ServiceDiversity]


class MTDSchedule:
    def __init__(self, mtd_interval_schedule: int, mtd_strategy_schedule: list):
        self.mtd_interval_schedule = mtd_interval_schedule
        self.mtd_strategy_schedule = mtd_strategy_schedule
        self.timestamps = None
        self.compromised_ratios = None

    def adapt_schedule_by_time(self, env):
        now = env.now
        if (self.timestamps[0] <= now < self.timestamps[1] or now >= self.timestamps[1]) and \
                self.mtd_interval_schedule > 15:
            self.mtd_interval_schedule /= 2
            logging.info('Shorten the time interval to %.1f at %.1fs!'
                         % (self.mtd_interval_schedule, now))
        return self.mtd_interval_schedule

    def adapt_schedule_by_compromised_ratio(self, env, compromised_ratio):
        now = env.now
        if (self.compromised_ratios[0] <= compromised_ratio < self.compromised_ratios[1]) and \
                len(self.mtd_strategy_schedule) < 4:
            logging.info('Current compromised ratio is %.1f, switch to shuffle mtd strategy schedule at %.1fs!'
                         % (compromised_ratio, now))
            self.mtd_strategy_schedule = MTD_SHUFFLE
        elif compromised_ratio >= self.compromised_ratios[1] and \
                len(self.mtd_strategy_schedule) < 5:
            logging.info('current compromised ratio is %.1f, switch to hybrid mtd strategy schedule at %.1fs!'
                         % (compromised_ratio, now))
            self.mtd_strategy_schedule = MTD_HYBRID

        return self.mtd_strategy_schedule

    def set_timestamps(self, timestamps: list):
        self.timestamps = timestamps

    def set_compromised_ratios(self, compromised_ratios):
        self.compromised_ratios = compromised_ratios

    def extend_mtd_strategy_schedule(self, mtd_strategies: list):
        self.mtd_strategy_schedule.extend(mtd_strategies)

    def get_mtd_interval_schedule(self):
        return self.mtd_interval_schedule

    def get_mtd_strategy_schedule(self):
        return self.mtd_strategy_schedule
