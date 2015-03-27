**Steps for training the classifier:**

First, notice that **AMICO ships with a default provenance classifier**. This means that you can immediately start using AMICO.

Notice, however, that until several download events have been collected (during what we call the "bootstrap" phase) and labeled in the download history database, you should expect AMICO to produce false positives. The classifier should start working better once historic download events have been collected during this "bootstrap" time period.

At the same time, once you have collected a good number of labeled download events, you may want to re-train the detection model to better tailor it to your own network environment, by following these steps:

  1. Set Database config parameters in `config.py`. See [Setup](https://code.google.com/p/amico/wiki/Setup) for more information
  1. Set the `training_start_date` and `training_days` parameters in `training_config.py`.
  1. Make sure you have enough training data.
  * We recommend collecting a sizable number of **labeled download events** before performing the training of the classifier (we automatically query VirusTotal to collect some ground truth). For example, we trained our classifier after collecting approximately 16,000 benign and 1,300 malware download instances. Until you collect enough samples, it may be better to use the default classifier model that comes with our current release of AMICO.
    * The `training_start_date` and `training_days` in the `training_config.py` essentially allow you to select the training samples from the download history database.
    * Notice that it is also advisable to have a _bootstrapping_ period of time before the `training_start_date`. The download instances collected during this bootstrapping period will be leveraged to computed the features for the actual training samples (please refer to our [ESORICS 2013 paper](http://www.perdisci.com/publications/publication-files/amico.pdf) for more information).

> You can use the following to get a count of malware and benign download examples with the current training parameters and data.
```
   $ python trainer.py -c
```
```
   Training start date: June 14, 2013
   Training end date: July 08, 2014
   # benign dumps 5671
   # malware dumps 101
```

> Notice that the `malware dumps` number is based on the ground truth provided by VirusTotal (for the "trusted" AV scanners). This number will not include samples that are "unknown" to VirusTotal, or that have too few AV labels assigned to them.

  1. Once you have enough training data, please run the following to generate a classifier model:
```
     $ python trainer.py
```
```
      .....
      New model trained: models/Apr08_14_003929.model
      Log file: logs/training/Apr08_14_003929.log
```
> > The file paths of the newly trained model and the related Weka log file are output by the script.
  1. To start using the new model for classification, change the `model_file` parameter in `config.py` to the newly trained model's file path.
