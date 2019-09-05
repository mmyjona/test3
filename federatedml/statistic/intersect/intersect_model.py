from arch.api.utils import log_utils
from fate_flow.entity.metric import Metric, MetricMeta
from federatedml.model_base import ModelBase
from federatedml.param.intersect_param import IntersectParam
from federatedml.statistic.intersect import RawIntersectionHost, RawIntersectionGuest, RsaIntersectionHost, \
    RsaIntersectionGuest
from federatedml.util import consts

LOGGER = log_utils.getLogger()


class IntersectModelBase(ModelBase):
    def __init__(self):
        super().__init__()
        self.intersection_obj = None
        self.intersect_num = -1
        self.intersect_rate = -1
        self.intersect_ids = None

        self.metric_name = "intersection"
        self.metric_namespace = "train"
        self.metric_type = "INTERSECTION"
        self.model_param = IntersectParam()
        self.role = None

        self.guest_party_id = None
        self.host_party_id = None

    def __init_intersect_method(self):
        LOGGER.info("Using {} intersection, role is {}".format(self.model_param.intersect_method, self.role))
        if self.model_param.intersect_method == "rsa":
            if self.role == consts.HOST:
                self.intersection_obj = RsaIntersectionHost(self.model_param)
            elif self.role == consts.GUEST:
                self.intersection_obj = RsaIntersectionGuest(self.model_param)
            else:
                raise ValueError("role {} is not support".format(self.role))

            self.intersection_obj.guest_party_id = self.guest_party_id
            self.intersection_obj.host_party_id = self.host_party_id

        elif self.model_param.intersect_method == "raw":
            if self.role == consts.HOST:
                self.intersection_obj = RawIntersectionHost(self.model_param)
            elif self.role == consts.GUEST:
                self.intersection_obj = RawIntersectionGuest(self.model_param)
            else:
                raise ValueError("role {} is not support".format(self.role))
        else:
            raise ValueError("intersect_method {} is not support yet".format(self.model_param.intersect_method))

    def fit(self, data):
        self.__init_intersect_method()
        self.intersect_ids = self.intersection_obj.run(data)
        LOGGER.info("Finish intersection")

        if self.intersect_ids:
            self.intersect_num = self.intersect_ids.count()
            self.intersect_rate = self.intersect_num * 1.0 / data.count()

        self.callback_metric(metric_name=self.metric_name,
                             metric_namespace=self.metric_namespace,
                             metric_data=[Metric("intersect_count", self.intersect_num),
                                          Metric("intersect_rate", self.intersect_rate)])
        self.tracker.set_metric_meta(metric_namespace=self.metric_namespace,
                                     metric_name=self.metric_name,
                                     metric_meta=MetricMeta(name=self.metric_name, metric_type=self.metric_type))

    def save_data(self):
        return self.intersect_ids

    def run(self, component_parameters=None, args=None):
        self.guest_party_id = component_parameters["role"]["guest"]
        self.host_party_id = component_parameters["role"]["host"]

        self._init_runtime_parameters(component_parameters)

        if self.need_cv:
            stage = 'cross_validation'
        elif self.need_one_vs_rest:
            stage = "one_vs_rest"
            if "model" in args:
                self._load_model(args)
        elif "model" in args:
            self._load_model(args)
            stage = "transform"
        elif "isometric_model" in args:
            self._load_model(args)
            stage = "fit"
        else:
            stage = "fit"

        if args.get("data", None) is None:
            return

        self._run_data(args["data"], stage)


class IntersectHost(IntersectModelBase):
    def __init__(self):
        super().__init__()
        self.role = consts.HOST


class IntersectGuest(IntersectModelBase):
    def __init__(self):
        super().__init__()
        self.role = consts.GUEST
