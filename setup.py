from setuptools import setup

setup(
    name='gns3api',
    version='0.1',
    description='Simple python module to access the GNS3 API',
    url='https://github.com/ehlers/gns3api',
    author='Bernhard Ehlers',
    author_email='be@bernhard-ehlers.de',
    license='GNU General Public License v3 (GPLv3)',
    long_description=open("README.md", "r").read(),
    long_description_content_type='text/markdown; charset=UTF-8',
    platforms='any',
    classifiers=['Development Status :: 3 - Alpha',
                 'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3',
                 'Topic :: Software Development :: Libraries',
                 ],
    py_modules = [ 'gns3api', ],
)
