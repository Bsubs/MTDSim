import os
import sys
current_directory = os.getcwd()
if not os.path.exists(current_directory + '\\experimental_data'):
    os.makedirs(current_directory + '\\experimental_data')
    os.makedirs(current_directory + '\\experimental_data\\plots')
    os.makedirs(current_directory + '\\experimental_data\\results')
sys.path.append(current_directory.replace('experiments', ''))
import warnings
import os
import sys
current_directory = os.getcwd()
if not os.path.exists(current_directory + '\\experimental_data'):
    os.makedirs(current_directory + '\\experimental_data')
    os.makedirs(current_directory + '\\experimental_data\\plots')
    os.makedirs(current_directory + '\\experimental_data\\results')
sys.path.append(current_directory.replace('experiments', ''))
import warnings
import matplotlib.pyplot as plt
warnings.filterwarnings("ignore")
plt.set_loglevel('WARNING')
from run import execute_simulation, create_experiment_snapshots, execute_ai_model, single_mtd_simulation, mtd_ai_simulation, multiple_mtd_simulation, specific_multiple_mtd_simulation
from mtdnetwork.mtd.completetopologyshuffle import CompleteTopologyShuffle
from mtdnetwork.mtd.ipshuffle import IPShuffle
from mtdnetwork.mtd.hosttopologyshuffle import HostTopologyShuffle
from mtdnetwork.mtd.portshuffle import PortShuffle
from mtdnetwork.mtd.osdiversity import OSDiversity
from mtdnetwork.mtd.servicediversity import ServiceDiversity
from mtdnetwork.mtd.usershuffle import UserShuffle
from mtdnetwork.mtd.osdiversityassignment import OSDiversityAssignment
import logging
import pandas as pd
import numpy as np
from math import pi
import matplotlib.pyplot as plt

# logging.basicConfig(format='%(message)s', level=logging.INFO)



class Experiment:
    def __init__(self, model_metric,epsilon, start_time, finish_time, mtd_interval, network_size,total_nodes, new_network,  model, trial, result_head_path, mtd_strategies = [
            CompleteTopologyShuffle,
            # HostTopologyShuffle,
            IPShuffle,
            OSDiversity,
            # PortShuffle,
            # OSDiversityAssignment,
            ServiceDiversity,
            # UserShuffle
        ],
        static_degrade_factor = 2000):
        # Learning Parameters
        self.epsilon = epsilon  # exploration rate

        # Simulator Settings
        self.start_time = start_time
        self.finish_time = finish_time

        self.total_nodes = total_nodes
        self.new_network = new_network
        self.model = model
        self.model_metric = model_metric
        self.other_schemes = [ "nomtd", 'simultaneous', 'random', 'alternative']
        self.trial = trial
        self.model_path = f"AI_model/models_will/new_models/{model_metric}/main_network_{model}.h5"
        self.mtd_strategies = mtd_strategies
        self.mtd_interval = mtd_interval
        self.network_size = network_size
        self.result_head_path = result_head_path
        self.static_degrade_factor = static_degrade_factor
        static_features = ["host_compromise_ratio",  "attack_path_exposure", "overall_asr_avg", "roa", "risk"]
        time_features = ["mtd_freq", "overall_mttc_avg", "time_since_last_mtd", "shortest_path_variability", "ip_variability", "attack_type"]
        if model_metric == "all_features":
            
            self.features =  {"static": static_features, "time": time_features}
        elif model_metric == "hybrid":
            self.features =  {"static": ["host_compromise_ratio",  "attack_path_exposure", "overall_asr_avg", "roa", "risk"], "time": ["mtd_freq", "overall_mttc_avg"]}
        else:
            if model_metric in static_features:
                self.features = {"static": [model_metric], "time": []}
            elif model_metric in time_features:
                self.features = {"static": [], "time": [model_metric]}


    def run_trials_ai_multi(self, folder):
        for i in range(self.trial):
            mtd = mtd_ai_simulation(self.features,f"{folder}/{self.model}", self.model_path, self.start_time, self.finish_time, self.total_nodes, new_network = self.new_network, 
                                                            mtd_interval=self.mtd_interval,network_size=self.network_size ,custom_strategies=self.mtd_strategies, static_degrade_factor = self.static_degrade_factor)  


    def run_trials(self, scheme):
        for i in range(self.trial):
            print("Trial_", i)
            print(scheme)
            if scheme == 'nomtd':
                mtd = single_mtd_simulation("nomtd", [None], 
                                                         mtd_interval=self.mtd_interval,network_size=self.network_size) 
            elif scheme == self.model:
      
                mtd = mtd_ai_simulation(self.features,self.model, self.model_path, self.start_time, self.finish_time, self.total_nodes, new_network = self.new_network, 
                                                            mtd_interval=self.mtd_interval,network_size=self.network_size ,custom_strategies=self.mtd_strategies, static_degrade_factor = self.static_degrade_factor)  

            else:
                mtd = specific_multiple_mtd_simulation(scheme, self.mtd_strategies, scheme, mtd_interval=self.mtd_interval,network_size=self.network_size)
        return 
    
    def get_result(self, path,model):
        if model not in self.other_schemes:
            if (self.mtd_interval == 50 and self.network_size == 150) or self.mtd_interval != 50:
                path = f'{path}/experiments/experimental_data/results/final_trials/mtd_interval_{self.mtd_interval}/{self.model_metric}_{self.mtd_interval}/{model}.csv'
            else:
                path = f'{path}/experiments/experimental_data/results/final_trials/network_size_{self.network_size}/{self.model_metric}_{self.network_size}/{model}.csv'
        else:
            path = f'{path}/experiments/experimental_data/results/other_schemes/{model}.csv'
        df = pd.read_csv(path)
        return df
    def get_result_checkpoint_median(self, model,checkpoints = 5):

        df = self.get_result(self.result_head_path, model).drop('Name', axis = 1)
        df['group'] = df.index // checkpoints
        # Group by the new column and calculate median
        df = df.groupby('group').mean().reset_index(drop=True)
 
        # Drop the 'group' column if you don't need it in the result
        df = df.drop(columns='group', errors='ignore')
        return df

    def get_result_stats(self, checkpoint_medians,stats_type = 'median'):
        if stats_type == 'median':
            return checkpoint_medians.median()
     
        return checkpoint_medians.std()
    
    def raw_result_stats_pipeline(self, scheme,run_trial = False, stats_type = 'median', checkpoints = 5):
        if run_trial:
            self.run_trials(scheme)

        checkpoint_medians = self.get_result_checkpoint_median(scheme, checkpoints)
     
        result = self.get_result_stats(checkpoint_medians,stats_type = stats_type)
        return result
        
    def scale_metrics(self, metrics_dict, normalization_dict):
        # Define which metrics should be maximized and which should be minimized
        metrics_to_maximize = {'time_to_compromise'}  
        metrics_to_minimize = {'host_compromise_ratio', 'attack_path_exposure', 'ASR', 'ROA', 'total_number_of_ports', "risk"}  

        scaled_metrics = {}

        for key, value in metrics_dict.items():
            if key in normalization_dict:
                norm_value = normalization_dict[key]
                if norm_value != 0:
                    if key in metrics_to_maximize:
                        # Normalize by dividing the metric value by the normalization value
                        scaled_metrics[key] = value / norm_value
                        # scaled_metrics[key] = 1 / (value / norm_value)
                        
                    elif key in metrics_to_minimize:
                        # Inverse the ratio for metrics to be minimized
                        scaled_metrics[key] = 1 / (value / norm_value)
             
                        # scaled_metrics[key] = value / norm_value
                    else:
                        # Handle cases where the metric is not in either category
                        scaled_metrics[key] = value
              
                else:
                    # Handle the case where norm_value is zero
                    scaled_metrics[key] = 1  # Or any other placeholder value as needed
            
            else:
                # Handle cases where normalization value is not defined
                scaled_metrics[key] = value  # Or handle differently as needed
            if key == "MEF":
                scaled_metrics[key] = value
        return scaled_metrics

    def scaled_pipeline(self, scheme,run_trial = False, stats_type = 'median'):
        nomtd_result = self.raw_result_stats_pipeline('nomtd',run_trial, stats_type)
        scheme_result = self.raw_result_stats_pipeline(scheme,run_trial, stats_type)
        scaled_scheme_result = self.scale_metrics(scheme_result.to_dict(), nomtd_result.to_dict())
        return {scheme:scaled_scheme_result}
    
    def multiple_scaled_pipeline(self,schemes,run_trial = False, stats_type = 'median', scaled_target = 'nomtd'):
        multi_schemes = {}

        nomtd_result = self.raw_result_stats_pipeline(scaled_target,run_trial, stats_type)
   
        for scheme in schemes:
            scheme_result = self.raw_result_stats_pipeline(scheme,run_trial, stats_type)
            scaled_scheme_result = self.scale_metrics(scheme_result.to_dict(), nomtd_result.to_dict())

            multi_schemes[scheme] = scaled_scheme_result
        return multi_schemes
    
  
