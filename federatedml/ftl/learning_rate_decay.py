import numpy as np


def sqrt_epoch_decay(init_learning_rate, epoch):
    if init_learning_rate is None or init_learning_rate <= 0:
        raise Exception("learning rate should bigger than zero")

    if epoch is None or epoch < 0:
        raise Exception("epoch should be bigger than or equal to zero")

    decay_factor = 1 / np.sqrt(epoch + 1)
    return init_learning_rate * decay_factor
