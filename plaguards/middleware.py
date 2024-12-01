from GuardModules.PlagParser import checktimefile


class validatefiletime:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if '' in request.path or 'media' in request.path or 'tools' in request.path or 'index' in request.path or 'tutorial' in request.path or 'about' in request.path or 'file_upload' in request.path or 'search' in request.path or 'redirect_result':
            checktimefile()
