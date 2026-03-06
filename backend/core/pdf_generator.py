"""
PDF Generator Module
Uses Jinja2 for HTML templating and xhtml2pdf to render compliant PDF reports.
"""
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
import io
import os
import logging
import datetime

logger = logging.getLogger(__name__)

# Base directory for the backend to locate the templates folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

# Initialize Jinja2 Environment
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))


def generate_pdf_report(threats: list, report_type: str) -> io.BytesIO:
    """
    Generate a PDF report from a list of threats based on the target audience (report_type).
    Valid report_types: 'executive', 'technical', 'managerial'.
    """
    if report_type not in ['executive', 'technical', 'managerial']:
        report_type = 'executive'
        
    template_name = f"{report_type}.html"
    
    try:
        template = env.get_template(template_name)
    except Exception as e:
        logger.error(f"Failed to load template {template_name}: {e}")
        raise ValueError(f"Template {template_name} not found.")

    # Prepare context
    context = {
        "threats": threats,
        "report_date": datetime.datetime.now().strftime("%B %d, %Y"),
        "report_type": report_type.capitalize(),
        "total_threats": len(threats)
    }

    # Render HTML string
    html_out = template.render(context)
    
    # Render PDF from HTML using xhtml2pdf
    result_file = io.BytesIO()
    
    # pisa.CreatePDF writes the PDF to the provided byte stream
    pisa_status = pisa.CreatePDF(
        src=html_out, 
        dest=result_file,
        encoding='utf-8'
    )
    
    if pisa_status.err:
        logger.error(f"xhtml2pdf encountered errors rendering {report_type} PDF.")
        raise Exception("Error rendering PDF report.")
        
    result_file.seek(0)
    return result_file
