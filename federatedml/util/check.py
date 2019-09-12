def check_eq(obj1, obj2, cast_error=False):
    res = (obj1 == obj2)
    if cast_error and not res:
        raise ValueError("{} != {}".format(obj1, obj2))
    return res