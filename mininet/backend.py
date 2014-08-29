class Backend(object):
    """
    A class to abstract the backend mechanism
    """

    def __init__(self):
        """Initialisation method"""
        print "Backend initialisation"
        self.test = 1

    def cleanup(self):
        print "Unimplemented virtual method"
