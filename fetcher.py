import requests
from threading import Thread
import random
import time
import traceback

'''
@author: hgao
'''


class Fetcher(Thread):
    """
    A fetcher thread that should be run as a daemon on a queue.

    Queue is an iterable of (idx, results, url) where:
        idx: position of the input, so we can sort results later after executing out of order
        results: a list object that this fetcher thread will append (idx, result) to
        url: the url to be fetched

    If a list of proxies and/or user_agents are provided, they will be randomly chosen upon each fetch.

    Optional parse_fn to parse the fetched html into a result, else will just return the html.
    Optional validation_fn to validate the parsed result.  If validation_fn(result) is False, the fetcher will retry.

    Returns:
        This fetcher will mutate and append a tuple (idx, result) to the results list (since this is thread safe).
        If there are exceptions and num_retries is exceeded, this fetcher will append (idx, errors) to the results list.
    """

    def __init__(self,
                 queue,
                 num_retries=3,
                 delay_sec=2.0,
                 timeout_sec=10.0,
                 proxies=None,
                 user_agents=None,
                 parse_fn=lambda x: x,
                 validation_fn=lambda x: True):

        Thread.__init__(self)
        self.queue = queue
        self.num_retries = num_retries
        self.delay_sec = delay_sec
        self.timeout_sec = timeout_sec
        self.proxies = proxies
        self.user_agents = user_agents
        self.parse_fn = parse_fn
        self.validation_fn = validation_fn

        self.num_proxies = len(self.proxies) if self.proxies else 0
        self.num_user_agents = len(self.user_agents) if self.user_agents else 0

        self.last_fetch_time = time.time() - self.delay_sec

    def run(self):
        """Consume from the queue"""
        while True:
            try:
                idx, results, url = self.queue.get()
                results.append(self.fetch(url, idx, results))
            finally:
                self.queue.task_done()

    def fetch(self, url, idx, results):
        """Try to fetch url"""
        num_retries = 0
        errors = []
        while num_retries < self.num_retries:
            self.sleep_until_min_fetch_delay()
            try:
                proxy = self.get_proxy()
                headers = self.get_headers()
                resp = requests.get(url, proxies=proxy, headers=headers, timeout=self.timeout_sec)
                result = self.parse_fn(resp.text)
                if self.validation_fn(result):
                    results.append((idx, result))
                else:
                    raise Exception('(Proxy: %s) Validation function did not pass for url: %s' % (proxy, url))

            except Exception as e:
                errors.append(e)
                traceback.print_exception(e, e, e.__traceback__)
                num_retries += 1

        # Max retries reached -- return errors instead of result
        results.append((idx, errors))

    def sleep_until_min_fetch_delay(self):
        deficit = self.delay_sec - (time.time() - self.last_fetch_time)
        if deficit > 0:
            time.sleep(deficit)
        self.last_fetch_time = time.time()

    def get_headers(self):
        """Get headers with random user agent and specify Connection: close"""
        header = requests.utils.default_headers()
        header['Connection'] = 'close'
        user_agent = self.get_user_agent()
        if user_agent:
            header['User-Agent'] = user_agent
        return header

    def get_proxy(self):
        """Get a random proxy if provided"""
        if self.proxies:
            proxy = self.proxies[random.randrange(self.num_proxies)]
            return {'http': 'http://%s' % proxy, 'https': 'https://%s' % proxy}
        else:
            return {}

    def get_user_agent(self):
        """Get a random user-agent if provided"""
        if self.user_agents:
            return self.user_agents[random.randrange(self.num_user_agents)]
        else:
            return ''


